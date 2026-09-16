rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_396_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_396_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b9cab0157a1e06a5e6fb017f3ba30d94230542a1fa46624c49e9f84ed373e2d"

  strings:
    $s1 = "Bare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}