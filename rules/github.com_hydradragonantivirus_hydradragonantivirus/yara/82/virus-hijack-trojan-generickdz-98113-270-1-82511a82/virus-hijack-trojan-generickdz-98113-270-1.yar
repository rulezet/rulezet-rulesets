rule Virus_Hijack_Trojan_GenericKDZ_98113_270_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_270_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e692f91d3f20e2e2002d133ba3894f7a9a82ee72e040e4076d31262c9a34626"

  strings:
    $s1 = "pawk{g" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}