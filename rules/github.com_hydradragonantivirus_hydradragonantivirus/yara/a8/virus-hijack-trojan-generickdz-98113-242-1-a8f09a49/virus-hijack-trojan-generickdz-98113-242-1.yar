rule Virus_Hijack_Trojan_GenericKDZ_98113_242_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_242_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f62f2b3360d67ccbf72a0f3767fe48e72589b57ecd5faf5f800a82cb893c7c34"

  strings:
    $s1 = "knoT(Z" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}