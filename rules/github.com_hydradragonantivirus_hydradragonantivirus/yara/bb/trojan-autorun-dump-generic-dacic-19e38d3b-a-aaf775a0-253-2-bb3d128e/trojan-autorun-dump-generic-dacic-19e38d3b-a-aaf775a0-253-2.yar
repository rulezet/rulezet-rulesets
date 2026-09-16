rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_253_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_253_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f58894bdb8b031bfdf89d3f6a632b9933e0af9c205c503922c5d12dee5035f6c"

  strings:
    $s1 = "KnoP:Xi1(" fullword ascii
    $s2 = "s&oboE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}