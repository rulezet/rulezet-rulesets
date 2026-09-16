rule Virus_Hijack_Trojan_GenericKDZ_98388_154_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_154_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65b6a5d7155d1d3d75b226973c80cbf208fe96938ba33e59c20d8f98aa42314e"

  strings:
    $s1 = "CUrT`R" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}