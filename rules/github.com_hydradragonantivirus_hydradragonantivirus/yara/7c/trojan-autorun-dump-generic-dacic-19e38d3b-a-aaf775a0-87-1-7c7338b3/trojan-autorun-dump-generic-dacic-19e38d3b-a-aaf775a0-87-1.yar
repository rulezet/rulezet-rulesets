rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_87_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_87_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e1fdd51117756a1ab700ced7605f2fda2634b681631f24c8151e6cb110b8ab0"

  strings:
    $s1 = ".~are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}