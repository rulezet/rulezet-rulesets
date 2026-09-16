rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_373_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_373_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70c78698bff91e8fd08558f0a0bbca4f365e959321c129390f3a37d5b05db92c"

  strings:
    $s1 = "pand services at the list price in effect at the " fullword ascii
    $s2 = "infringement claim could have been avoided by`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}