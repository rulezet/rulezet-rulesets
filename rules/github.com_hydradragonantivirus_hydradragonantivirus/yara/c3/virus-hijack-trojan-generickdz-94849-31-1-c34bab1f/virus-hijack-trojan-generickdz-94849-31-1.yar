rule Virus_Hijack_Trojan_GenericKDZ_94849_31_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.94849_31_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55f8bf8858e8b1d371a12a9da2b28d14bdc26a891c64d115ad650e2f7f351ae8"

  strings:
    $s1 = "OXan{u" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}