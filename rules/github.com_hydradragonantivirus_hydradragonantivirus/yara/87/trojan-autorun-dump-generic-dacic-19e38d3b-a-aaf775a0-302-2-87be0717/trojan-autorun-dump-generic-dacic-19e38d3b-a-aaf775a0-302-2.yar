rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_302_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_302_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f8cb9db062a03ad5890274af0671b0d2888cca909c19afde48af90ebdf29489"

  strings:
    $s1 = ".?AgEd" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}