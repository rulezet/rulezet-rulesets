rule Virus_Hijack_Trojan_GenericKDZ_98113_107_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_107_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed18157e2c9932b7b6d727f85360a2b66db0f90a9f113ed3aafc5eed50bb12b9"

  strings:
    $s1 = "fLuE':.-A" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}