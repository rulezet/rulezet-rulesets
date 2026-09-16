rule Virus_Hijack_Gen_Trojan_ShellObject_fKX_aeBHSxm_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fKX@aeBHSxm_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f51a154b2296b60647814a9f635698910ca10532ee61a7fab8512996fc7b4e63"

  strings:
    $s1 = "a2IRE_OLSA_V120103_Def_V122304 Page 1 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}