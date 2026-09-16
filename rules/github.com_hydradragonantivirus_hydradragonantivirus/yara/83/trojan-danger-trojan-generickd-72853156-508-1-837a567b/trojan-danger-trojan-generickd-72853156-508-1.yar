rule Trojan_Danger_Trojan_GenericKD_72853156_508_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_508_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad0a7b6e4c06e10c21e2b5a32391ac10a4cdb0fbc66ff4a40a11686bc13c4190"

  strings:
    $s1 = "^OLE initialization b nbm  gh ailed.  Make sure that the OLE libraries are the correct version." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}