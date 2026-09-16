rule Virus_Hijack_Trojan_GenericKDZ_98113_138_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_138_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "702bc1e3d31a6bd7a8c61cd321e604aff4175a09af4b582e911d1a0e4d6e0f4c"

  strings:
    $s1 = "SEgo[?" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}