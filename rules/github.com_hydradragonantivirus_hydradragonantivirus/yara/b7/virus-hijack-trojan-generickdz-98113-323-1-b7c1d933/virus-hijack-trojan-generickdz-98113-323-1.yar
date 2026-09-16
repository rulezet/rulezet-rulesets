rule Virus_Hijack_Trojan_GenericKDZ_98113_323_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_323_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b0da7d3d49c1c596d06ac9ff96f095e92a2ae1f887e899349e2115dbcac713c"

  strings:
    $s1 = "FoGO*:" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}