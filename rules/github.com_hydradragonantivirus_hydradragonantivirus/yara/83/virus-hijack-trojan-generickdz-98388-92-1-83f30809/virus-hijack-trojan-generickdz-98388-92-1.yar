rule Virus_Hijack_Trojan_GenericKDZ_98388_92_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_92_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1cc0cf540c0f4edd0b72d9ccc019c06bf5a926cb35e00513a786153a4c348663"

  strings:
    $s1 = "*@JaKo" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}