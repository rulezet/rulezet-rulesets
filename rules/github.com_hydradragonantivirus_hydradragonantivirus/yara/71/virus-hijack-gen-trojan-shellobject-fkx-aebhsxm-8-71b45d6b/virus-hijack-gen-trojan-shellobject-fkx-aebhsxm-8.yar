rule Virus_Hijack_Gen_Trojan_ShellObject_fKX_aeBHSxm_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fKX@aeBHSxm_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6da0aede1445f0cfc644c72179638435f45fee390cc9b5983e84165510b82f7"

  strings:
    $s1 = "s0IRE_OLSA_V120103_Def_V122304 Page 1 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}