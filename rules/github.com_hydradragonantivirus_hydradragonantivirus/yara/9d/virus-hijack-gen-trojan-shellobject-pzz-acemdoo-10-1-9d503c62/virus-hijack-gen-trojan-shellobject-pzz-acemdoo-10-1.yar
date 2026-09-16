rule Virus_Hijack_Gen_Trojan_ShellObject_pzZ_aCEmdoo_10_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.pzZ@aCEmdoo_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9560d49c96c25abcc0119c0a687b40a78238d3bf18d2f512b46f763b90c0978d"

  strings:
    $s1 = "z.Buf&tRAM*z" fullword ascii
    $s2 = "BaUd'g" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}