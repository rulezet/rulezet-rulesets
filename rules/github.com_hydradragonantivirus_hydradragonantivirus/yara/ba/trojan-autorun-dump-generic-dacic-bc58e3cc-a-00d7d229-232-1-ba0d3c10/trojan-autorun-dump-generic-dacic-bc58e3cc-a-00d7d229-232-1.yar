rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_232_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_232_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ac896f226b4327d5b90ec7d224eb6fd50fef532742a171daae15a8799985b37"

  strings:
    $s1 = "\\.Oracle does not warrant that the Oracle Universi" fullword ascii
    $s2 = "Microsoft products. You agree that w`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}