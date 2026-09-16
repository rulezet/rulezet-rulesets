rule Virus_Hijack_Trojan_GenericKDZ_98388_90_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_90_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e61690227547889a14df1485ed990082060b1aa630ce4299f9b5d6f74f4ca8f"

  strings:
    $s1 = "QUit%C" fullword ascii
    $s2 = "MUrks+K" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}