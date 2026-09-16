rule Trojan_Autorun_Trojan_GenericKDZ_94847_227_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_227_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b4602264c7267891bf052f20c7c8b244b9b7590726adc95d93ecedf8484ce32"

  strings:
    $s1 = "Wywhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}