rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_28_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_28_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a06fb69ae9469d70b350bdd24a1b8a771634ef009886e9e14f4b4765cbcdea19"

  strings:
    $s1 = "KuLa{lf" fullword ascii
    $s2 = "tO@CEPe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}