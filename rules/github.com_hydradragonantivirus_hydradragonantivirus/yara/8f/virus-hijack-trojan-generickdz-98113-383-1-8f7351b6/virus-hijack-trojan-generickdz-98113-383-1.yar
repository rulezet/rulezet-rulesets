rule Virus_Hijack_Trojan_GenericKDZ_98113_383_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_383_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5bbd66167b5740d5a670881cc521914839dd02730acc417a9556b6d17cf37b33"

  strings:
    $s1 = "#[liFO" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}