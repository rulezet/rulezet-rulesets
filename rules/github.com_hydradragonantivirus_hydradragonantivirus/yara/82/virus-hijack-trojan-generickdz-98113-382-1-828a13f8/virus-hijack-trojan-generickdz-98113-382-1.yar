rule Virus_Hijack_Trojan_GenericKDZ_98113_382_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_382_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0868c84461774371322f4ac7ca82d7fb418115867fb38aaa1f55e8923db00975"

  strings:
    $s1 = "peRi>h" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}