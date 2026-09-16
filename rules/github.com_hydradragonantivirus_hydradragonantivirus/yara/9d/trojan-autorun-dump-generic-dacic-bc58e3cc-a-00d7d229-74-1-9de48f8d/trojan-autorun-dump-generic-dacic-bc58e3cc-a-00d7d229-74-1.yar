rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_74_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_74_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1101f7aaa2118b345f0163fc44d8fafeb4187fac3d71e2aa08955b10c743b0d8"

  strings:
    $s1 = "nyour entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}