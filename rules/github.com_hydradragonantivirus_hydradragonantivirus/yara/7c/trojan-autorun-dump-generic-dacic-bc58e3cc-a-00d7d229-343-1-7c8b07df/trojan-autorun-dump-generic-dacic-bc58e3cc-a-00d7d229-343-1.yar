rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_343_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_343_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e1add72e8dcd6f28447bb7b4ea2d769edac10fcc3f87b59dc12fb0bfdf5be46"

  strings:
    $s1 = "M=active employee population and not the number of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}