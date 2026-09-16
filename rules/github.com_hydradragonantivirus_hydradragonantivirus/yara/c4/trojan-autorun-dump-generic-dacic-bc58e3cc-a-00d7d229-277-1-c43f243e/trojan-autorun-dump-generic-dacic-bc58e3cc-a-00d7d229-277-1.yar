rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_277_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_277_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bbec98c7214758cfd84f6fe9cda311ae57d5d487f7e87143cf4067a0f3d7f850"

  strings:
    $s1 = "nprevent either party from disclosing the terms o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}