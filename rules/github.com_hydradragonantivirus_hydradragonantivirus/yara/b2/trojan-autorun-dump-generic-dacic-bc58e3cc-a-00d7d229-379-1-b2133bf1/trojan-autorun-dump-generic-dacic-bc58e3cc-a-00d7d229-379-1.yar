rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_379_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_379_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a2a74053c06d0266d174985cd468c9c12155186391f701bac835d2593a85370d"

  strings:
    $s1 = "user minimum tabl" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}