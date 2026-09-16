rule Trojan_Danger_Trojan_GenericKD_72853156_156 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_156.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "562faf7b5f195f8705c92bc399130695080eae96c2e60c4e163cfb1d6fd86dd7"

  strings:
    $s1 = "System Configuration.lnk.exe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}