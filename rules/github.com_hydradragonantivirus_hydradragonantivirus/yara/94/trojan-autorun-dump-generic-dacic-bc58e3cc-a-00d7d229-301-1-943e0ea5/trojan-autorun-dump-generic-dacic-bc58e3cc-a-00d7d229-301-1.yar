rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_301_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_301_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f2a93be1daec5035e5316776f7cb932c2540f33ed053e822f00f593340610b1"

  strings:
    $s1 = "w/If you want to find out more about academic soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}