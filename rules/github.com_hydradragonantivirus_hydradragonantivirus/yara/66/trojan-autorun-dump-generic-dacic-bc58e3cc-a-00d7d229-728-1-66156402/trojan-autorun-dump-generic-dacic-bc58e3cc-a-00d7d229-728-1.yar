rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_728_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_728_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1088e5cdb78b0341877b2ced5548907647e364b05cc143979ab12dd06df2e547"

  strings:
    $s1 = "}of the software and a separate license for each copy. Content protected by digital rights management" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}