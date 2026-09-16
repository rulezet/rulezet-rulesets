rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_324_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_324_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d3db0eed87ab62420c4240e2d2477d4a2a678b436428838e15bac53b0e8b517"

  strings:
    $s1 = "tcHU!+" fullword ascii
    $s2 = "OOnt!7B4%" fullword ascii
    $s3 = "TcHe{<" fullword ascii
    $s4 = ">Room};m" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}