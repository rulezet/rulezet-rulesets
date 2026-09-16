rule Virus_Hijack_Trojan_GenericKDZ_98113_23_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_23_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ee891dbe97f94ee1b24b386d9289b458f2f42d2eed150efb70d781cfd2f942f"

  strings:
    $s1 = "PiLL;7" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}