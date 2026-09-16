rule Virus_Hijack_Trojan_GenericKDZ_74550_317_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_317_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b3552c7b381d613ba3f524ff2271cbedf9a6445cb599d75aa09e5f261557d6d"

  strings:
    $s1 = "jiva&mj" fullword ascii
    $s2 = "|`peAn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}