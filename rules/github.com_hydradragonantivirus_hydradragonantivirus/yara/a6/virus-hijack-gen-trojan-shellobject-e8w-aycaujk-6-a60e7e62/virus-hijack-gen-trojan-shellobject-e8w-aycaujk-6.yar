rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aycAujk_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aycAujk_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36329142833efa47e44ad6493d3b65c5d0360680a3e0ff520d2c86142862fa76"

  strings:
    $s1 = "&Workshop" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}