rule Virus_Hijack_Trojan_GenericKDZ_98113_228 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_228.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64e8574f16226b9220b34d78f73eb9be1887999e82d0ba13961d755a21bf2d7e"

  strings:
    $s1 = "JWhundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}