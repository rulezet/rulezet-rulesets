rule Virus_Hijack_Trojan_GenericKDZ_74550_70_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_70_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6413555603d8a5b27282063d65331ce2e12e7f8e94345c705c08d9f6c54076d"

  strings:
    $s1 = "\"(snib" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}