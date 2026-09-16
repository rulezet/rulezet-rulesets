rule Virus_Hijack_Trojan_GenericKDZ_98113_354 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_354.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65f54526ec443e923857f78899ab81009f2d75b144b90e31015143e3f36270dc"

  strings:
    $s1 = "hhundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}