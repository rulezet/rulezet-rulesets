rule Virus_Hijack_Trojan_GenericKDZ_103545_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41a6ccd1201c1e1665ba95869e32cf230f48bbad5d948b1682600760076ef847"

  strings:
    $s1 = "~software features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}