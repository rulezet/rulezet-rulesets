rule Trojan_Autorun_Trojan_GenericKDZ_94847_122_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_122_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8b957b7f0fb00f57578cd5919201bc71dcc55024c65536076fce31d40a6ec7f"

  strings:
    $s1 = "CAAmerica, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}