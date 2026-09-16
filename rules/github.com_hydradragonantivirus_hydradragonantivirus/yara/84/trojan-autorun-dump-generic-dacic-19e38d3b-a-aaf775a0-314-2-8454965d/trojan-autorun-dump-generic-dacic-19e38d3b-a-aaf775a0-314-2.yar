rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_314_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_314_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db729eb33cf1e039ea721d8c50f285d714721fdf96521c4a7c1371959f39de8e"

  strings:
    $s1 = "n?devA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}