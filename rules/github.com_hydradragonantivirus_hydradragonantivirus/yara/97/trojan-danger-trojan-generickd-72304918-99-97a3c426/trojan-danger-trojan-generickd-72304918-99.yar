rule Trojan_Danger_Trojan_GenericKD_72304918_99 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_99.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1bb21dbded918e5d3d280cacf6152da1650f5db83c9571339aed389642ec0a3b"

  strings:
    $s1 = "ODBC Data Sources (32-bit).lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}