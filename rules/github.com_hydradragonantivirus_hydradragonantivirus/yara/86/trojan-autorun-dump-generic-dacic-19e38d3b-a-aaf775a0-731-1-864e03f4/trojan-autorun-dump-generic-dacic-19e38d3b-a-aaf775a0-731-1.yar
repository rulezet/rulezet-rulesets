rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_731_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_731_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8fc03431642bdf2bbdd7c6335f7e36f3230d96c16e225ba9480f0c0f190c928"

  strings:
    $s1 = "<secml_malware.attack.blackbox.c_wrapper_phi.CEnd2EndWrapperPhi object at 0x7f5c08ec3d00>, 'is_d" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}