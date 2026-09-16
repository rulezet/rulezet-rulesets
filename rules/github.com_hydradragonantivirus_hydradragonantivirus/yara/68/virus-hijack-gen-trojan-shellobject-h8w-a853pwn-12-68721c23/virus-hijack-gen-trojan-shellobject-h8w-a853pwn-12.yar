rule Virus_Hijack_Gen_Trojan_ShellObject_h8W_a853Pwn_12 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.h8W@a853Pwn_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "887ea7df1525edbb2d9757e389b243739a08af04eedc1d8dd91fcadf1c9423ca"

  strings:
    $s1 = "s Work!]A" fullword ascii
    $s2 = "&Dpde Photo" fullword ascii
    $s3 = "p@gram Jm6-" fullword ascii
    $s4 = "w?(null" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}