rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_696_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_696_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e95bd9d25b95df71e3b3359c21c8c28daec5d8177bbc84d576cd90650fcd9b1d"

  strings:
    $s1 = "s policies regarding financing which " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}