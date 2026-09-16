rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_271_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_271_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc62923e99889ad9c2f96a68a3e210372ccc16c4b1ce865ebd65bfa9c7e51d1f"

  strings:
    $s1 = "?bEld?*" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}