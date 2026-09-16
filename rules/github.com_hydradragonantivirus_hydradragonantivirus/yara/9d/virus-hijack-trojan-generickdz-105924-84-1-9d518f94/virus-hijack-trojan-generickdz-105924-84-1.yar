rule Virus_Hijack_Trojan_GenericKDZ_105924_84_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_84_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c8e4b2e7d5a51d08f9475ff8c5a6f2bcd4d4194bc94822aa11d9546d5792e9c"

  strings:
    $s1 = "%!bILL" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}