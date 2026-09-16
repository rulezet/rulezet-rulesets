rule Virus_Hijack_Trojan_GenericKDZ_98113_365_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_365_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c445d85ec653000d5ca1c0512f8aaa75fa47c11d7d8f082e84938856fe72b1e"

  strings:
    $s1 = "piEn{}k" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}