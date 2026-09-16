rule Virus_Hijack_Trojan_GenericKDZ_103285_763 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_763.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d88b162569523424268a19e695a3f0ef1ba4b9a0b3964eb5e130c122bd01998c"

  strings:
    $s1 = "$dispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}