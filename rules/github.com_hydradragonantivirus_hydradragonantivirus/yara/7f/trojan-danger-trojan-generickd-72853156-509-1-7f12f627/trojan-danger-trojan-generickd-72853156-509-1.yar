rule Trojan_Danger_Trojan_GenericKD_72853156_509_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_509_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b3e11612851229a14c9ae0c46d97b19a365f3b9244bcfee8c9664589451cb186"

  strings:
    $s1 = "^OLE initialization b nbm  gh ailed.  Make sure that the OLE libraries are the correct version." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}