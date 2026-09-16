rule Virus_Hijack_Trojan_GenericKDZ_98388_40_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_40_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c7c50a83eda6d646be64f9129bf7c9a20c1a19ef363383e844e344e3608332bb"

  strings:
    $s1 = "V*EkKA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}