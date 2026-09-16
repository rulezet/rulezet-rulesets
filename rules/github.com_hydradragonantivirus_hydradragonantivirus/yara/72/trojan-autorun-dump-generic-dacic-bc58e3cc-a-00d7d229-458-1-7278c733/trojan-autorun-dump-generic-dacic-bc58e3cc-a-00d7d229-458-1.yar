rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_458_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_458_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3983027c67176947df1db26dbfbd13597460706fad7851cf43d6e9351f03390"

  strings:
    $s1 = "s policies regarding financing which " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}