rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_9_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb3fceb76ea305f4860e364ef604a27e7c437978763d04ed553e6eba0c306850"

  strings:
    $s1 = "cLprevent either party from disclosing the terms o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}