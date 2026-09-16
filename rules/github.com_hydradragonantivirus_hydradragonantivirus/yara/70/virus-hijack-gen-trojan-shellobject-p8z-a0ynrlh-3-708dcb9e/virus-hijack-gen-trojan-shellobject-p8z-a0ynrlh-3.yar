rule Virus_Hijack_Gen_Trojan_ShellObject_p8Z_a0YNrLh_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.p8Z@a0YNrLh_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1bbe4b713b6a260943198e6d6a2fc91a7e0f8ad7ccb3662242814b6fbd5d5ec9"

  strings:
    $s1 = "jAKE*3;" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}