rule Virus_Hijack_Trojan_GenericKDZ_103285_473 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_473.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ffba80f9eb9fe1ee7db66d9766174ccb8c1238e67e3a47d249268dd9349d6841"

  strings:
    $s1 = "`University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}