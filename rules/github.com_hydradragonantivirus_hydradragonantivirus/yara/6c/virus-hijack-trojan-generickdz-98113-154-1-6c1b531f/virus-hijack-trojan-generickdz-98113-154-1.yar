rule Virus_Hijack_Trojan_GenericKDZ_98113_154_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_154_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00d8d45ece0c46d6d252a8c0fd5f7915afcfea020bfe69eccc069c66525e7bed"

  strings:
    $s1 = "#husH%nN" fullword ascii
    $s2 = "Dray{Y" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}