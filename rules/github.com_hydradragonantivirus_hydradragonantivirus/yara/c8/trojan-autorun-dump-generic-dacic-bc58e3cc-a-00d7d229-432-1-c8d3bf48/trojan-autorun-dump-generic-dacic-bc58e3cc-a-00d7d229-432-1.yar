rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_432_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_432_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "456449eada6716a96e1bf8e904b792ae04d9c27868bf804184a911322394a8ac"

  strings:
    $s1 = "7If you want to find out more about academic soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}