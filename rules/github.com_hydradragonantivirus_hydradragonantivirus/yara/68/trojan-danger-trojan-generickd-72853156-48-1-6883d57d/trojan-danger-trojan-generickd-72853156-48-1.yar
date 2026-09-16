rule Trojan_Danger_Trojan_GenericKD_72853156_48_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_48_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e402655a34a2086ce3db153b89460e0dedd7df86496567a6d4d0e1b4bbb8e4e8"

  strings:
    $s1 = "^OLE initialization b nbm  gh ailed.  Make sure that the OLE libraries are the correct version." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}