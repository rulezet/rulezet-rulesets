rule Virus_Hijack_Trojan_GenericKDZ_98113_281_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_281_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eeaf429681c6d324918d83bf7856a0a10170046f8184df402393ba04446bc57d"

  strings:
    $s1 = "S]SIle" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}