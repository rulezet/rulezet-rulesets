rule Trojan_Autorun_Trojan_GenericKDZ_94847_314_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_314_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a8cf29a38c344b9d4b537d012a7d6664bf66ad3bc11a80674e516e6360b6df43"

  strings:
    $s1 = "1Uorders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}