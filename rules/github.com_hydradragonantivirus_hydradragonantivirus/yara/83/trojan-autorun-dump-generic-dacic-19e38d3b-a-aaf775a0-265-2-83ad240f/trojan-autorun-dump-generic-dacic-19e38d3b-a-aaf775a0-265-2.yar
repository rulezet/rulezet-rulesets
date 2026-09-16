rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_265_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_265_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc9c4e57775102bcd34466e4a8f2d08d23152793dc4ad1f49063e041b09e9794"

  strings:
    $s1 = "bOWl}R" fullword ascii
    $s2 = "uDAl%J" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}