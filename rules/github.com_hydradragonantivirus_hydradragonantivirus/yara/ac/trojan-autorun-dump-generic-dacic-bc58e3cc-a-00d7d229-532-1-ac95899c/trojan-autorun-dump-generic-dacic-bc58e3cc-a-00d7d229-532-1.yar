rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_532_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_532_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e25706f30171b00855f4dd977c951ce4290dc5088b568f97b6cc192f230b6cf"

  strings:
    $s1 = "#your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}