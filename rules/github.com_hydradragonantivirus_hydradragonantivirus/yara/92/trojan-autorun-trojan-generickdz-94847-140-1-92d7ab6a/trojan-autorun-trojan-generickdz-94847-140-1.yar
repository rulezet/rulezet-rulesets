rule Trojan_Autorun_Trojan_GenericKDZ_94847_140_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_140_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "daac3de2e7d4d72e716de4560ceb332406c1f274d25829770df6ecea2dbb384e"

  strings:
    $s1 = "b>orders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}