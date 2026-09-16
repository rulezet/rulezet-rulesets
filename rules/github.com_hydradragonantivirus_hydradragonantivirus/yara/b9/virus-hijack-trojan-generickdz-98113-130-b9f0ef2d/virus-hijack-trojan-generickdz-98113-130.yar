rule Virus_Hijack_Trojan_GenericKDZ_98113_130 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_130.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f99d6eb3ad8421f7136070031713bee1d7469c6fb831c074665d1d1c6de0e4b"

  strings:
    $s1 = "U4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}