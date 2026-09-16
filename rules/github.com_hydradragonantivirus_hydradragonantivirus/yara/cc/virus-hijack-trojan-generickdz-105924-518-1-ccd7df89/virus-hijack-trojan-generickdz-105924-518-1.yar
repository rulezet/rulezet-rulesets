rule Virus_Hijack_Trojan_GenericKDZ_105924_518_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_518_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "871a69d885f76a19068ff9a2614678974c712d51141c6272b090ff26ca69dba7"

  strings:
    $s1 = "{horN." fullword ascii
    $s2 = "piST :" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}