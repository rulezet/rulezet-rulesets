rule Trojan_Autorun_Trojan_GenericKD_67169344_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.67169344_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa051d67fd19bfefdf83249ed05e15fb3666c5c0546975277861771909855e9b"

  strings:
    $s1 = ";by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}