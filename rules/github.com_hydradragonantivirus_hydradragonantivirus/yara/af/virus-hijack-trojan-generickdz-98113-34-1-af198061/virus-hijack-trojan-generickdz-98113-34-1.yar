rule Virus_Hijack_Trojan_GenericKDZ_98113_34_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_34_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb766bd5d9af807ef338b70ba70837b9e619e18bfdf70dcc58978b176cf13a36"

  strings:
    $s1 = "auge}9" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}