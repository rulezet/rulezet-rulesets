rule Virus_Hooker_Trojan_Generic_30984256_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hooker_Trojan.Generic.30984256_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d33bd2711bd16e64c6815b7a22cd3d38feb67aea46299a7b1b20d3c3beda44aa"

  strings:
    $s1 = "rAdA}!" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}