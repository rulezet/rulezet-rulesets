rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_736_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_736_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5d8bf1ba3f3fa3258cba2884617aaf56071165619a2c3e7507bfa48749679b5"

  strings:
    $s1 = "PTrade Compliance web site which can be accessed at http://oracle.com/contracts. You agree that no data, information," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}