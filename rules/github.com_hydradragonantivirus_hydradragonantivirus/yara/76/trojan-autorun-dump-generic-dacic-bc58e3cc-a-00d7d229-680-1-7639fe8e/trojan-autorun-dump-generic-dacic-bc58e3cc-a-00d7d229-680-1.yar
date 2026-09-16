rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_680_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_680_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f97b473305f7204ec14810497abd7ffa55d824e8fa14aa8d2bf5b4a2d64611e1"

  strings:
    $s1 = "\"/your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}