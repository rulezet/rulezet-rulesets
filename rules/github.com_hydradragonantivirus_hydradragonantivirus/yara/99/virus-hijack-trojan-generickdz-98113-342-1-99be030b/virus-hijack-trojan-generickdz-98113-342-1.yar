rule Virus_Hijack_Trojan_GenericKDZ_98113_342_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_342_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9fd17fffa716bab58a8f138cbe2e6a03e46d99bf27b82dd74a809e461c381c5"

  strings:
    $s1 = "SIer&S" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}