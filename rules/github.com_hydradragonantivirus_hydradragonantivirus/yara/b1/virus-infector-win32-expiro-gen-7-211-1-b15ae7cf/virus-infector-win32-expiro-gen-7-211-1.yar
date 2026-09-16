rule Virus_Infector_Win32_Expiro_Gen_7_211_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_211_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36fa17d169f1b0ef979a2f2ff5404b397d34caf1db59aa2ef827f8ecbe85a929"

  strings:
    $s1 = "function time(){return new Date().getTime()}" fullword ascii
    $s2 = "function uncompile(so)" fullword ascii
    $s3 = "<embed autoplay=\"true\" src=\"sound.mp3\"  width=\"1\" height=\"1\" />" fullword ascii
    $s4 = "function time(){return Math.random()}" fullword ascii
    $s5 = "source = escape(so);" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}