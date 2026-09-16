rule Virus_Hijack_Trojan_GenericKDZ_98113_378_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_378_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58a84dfd7806ba0c0b6bc4886e9fa4d3a3b6c772d7fabba28f5ffc75dbc5e596"

  strings:
    $s1 = "??GUsLe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}