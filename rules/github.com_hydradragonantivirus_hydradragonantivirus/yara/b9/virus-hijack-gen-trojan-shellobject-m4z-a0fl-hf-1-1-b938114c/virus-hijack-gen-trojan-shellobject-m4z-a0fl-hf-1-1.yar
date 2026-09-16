rule Virus_Hijack_Gen_Trojan_ShellObject_m4Z_a0fL_hf_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m4Z@a0fL!hf_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2cc3d1e51067bea1f365b6a7c44aa02a391ac5812d3849c6e09341243716011"

  strings:
    $s1 = "FELs]xC" fullword ascii
    $s2 = "polL&p" fullword ascii
    $s3 = "r!wHAT" fullword ascii
    $s4 = "e?pImp" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}