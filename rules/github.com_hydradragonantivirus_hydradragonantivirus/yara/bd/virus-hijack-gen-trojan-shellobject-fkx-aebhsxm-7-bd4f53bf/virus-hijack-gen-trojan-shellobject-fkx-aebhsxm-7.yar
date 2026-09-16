rule Virus_Hijack_Gen_Trojan_ShellObject_fKX_aeBHSxm_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fKX@aeBHSxm_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c5e1fb6ba86c0755f77da554553cd51266e04979166500c1a3c0813bcbefaa2"

  strings:
    $s1 = "\\IRE_OLSA_V120103_Def_V122304 Page 1 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}