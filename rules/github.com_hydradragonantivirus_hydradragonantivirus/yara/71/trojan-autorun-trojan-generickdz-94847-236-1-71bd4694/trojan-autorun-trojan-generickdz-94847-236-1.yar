rule Trojan_Autorun_Trojan_GenericKDZ_94847_236_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_236_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ed4c8975b2ec1bab11429d19bfd96289fec179f6b9ded44953590d4cea768bd"

  strings:
    $s1 = "SAmerica, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}