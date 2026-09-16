rule Trojan_Autorun_Trojan_GenericKDZ_94847_168_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_168_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d628a88e0531b8b3ccf97912c72c91b926784928378dfc2a080cd83a27584041"

  strings:
    $s1 = "cAmerica, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}