rule Virus_Hijack_Trojan_GenericKDZ_105924_95_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_95_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b27070d0da8e1056b05ea7a075f8fb4c187db88a6f2cc9d855442beeb1a5bece"

  strings:
    $s1 = "oO2:BALD" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}