rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ayJVeyi_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ayJVeyi_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e97e3b298f1bd9af2563c5c1c7d2383d566b7bfa8b6d56fe6795bf53fc9aa873"

  strings:
    $s1 = "Elsewise" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}