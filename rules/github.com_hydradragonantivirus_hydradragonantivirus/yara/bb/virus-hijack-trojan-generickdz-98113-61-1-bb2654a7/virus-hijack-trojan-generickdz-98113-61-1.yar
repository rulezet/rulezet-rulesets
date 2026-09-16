rule Virus_Hijack_Trojan_GenericKDZ_98113_61_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_61_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cd525a4f741fda775896fedfa01a66864bb52444674069346851ab4dfd8942e"

  strings:
    $s1 = "d{ABeY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}