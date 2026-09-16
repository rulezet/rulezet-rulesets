rule Virus_Hijack_Trojan_GenericKDZ_98388_120_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_120_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "211f667ad82ce562e4e03efe89d1d0bbbc5f10bc4edb9f857f017227c2badc09"

  strings:
    $s1 = "roEY,u" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}