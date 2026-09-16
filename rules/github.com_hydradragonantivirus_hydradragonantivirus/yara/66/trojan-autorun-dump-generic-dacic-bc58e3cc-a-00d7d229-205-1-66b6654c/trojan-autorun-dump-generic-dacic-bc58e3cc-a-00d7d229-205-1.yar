rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_205_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_205_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97b878fe121e4dedec1d2dff150cf3b1c19248a4d10e0cd0e4a5908c490fb1ac"

  strings:
    $s1 = "dhaN?}`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}