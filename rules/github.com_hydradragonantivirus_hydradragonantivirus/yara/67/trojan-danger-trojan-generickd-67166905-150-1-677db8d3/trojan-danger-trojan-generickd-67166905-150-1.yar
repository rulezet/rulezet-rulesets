rule Trojan_Danger_Trojan_GenericKD_67166905_150_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_150_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "57f6c89ae2ea4b185f0ec604909e09d35d9865df7a64c0214d9d3d452c445e50"

  strings:
    $s1 = "tpurchase orders transmitted from Oracle Purchasing, during a 12 month period. You may not exceed the licensed number of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}