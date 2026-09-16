rule Trojan_Autorun_Trojan_GenericKDZ_94847_340_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_340_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e8fc1ccc951db10b9c48f9d0487e75c16d5f43d2075de361b1d2202949f8500"

  strings:
    $s1 = "=America, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}