rule Virus_Hijack_Trojan_GenericKDZ_98113_213_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_213_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b1ceb8376f599245c3b2b7d130b3d91e8a0c2e17b1f7dd7f0bd5426327ccdd2b"

  strings:
    $s1 = "?SeAH{" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}