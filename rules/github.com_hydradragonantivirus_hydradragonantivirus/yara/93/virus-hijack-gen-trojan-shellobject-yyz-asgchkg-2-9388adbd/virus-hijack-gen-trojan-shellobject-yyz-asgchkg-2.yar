rule Virus_Hijack_Gen_Trojan_ShellObject_yyZ_aSgChKg_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.yyZ@aSgChKg_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1afc3f904306aace5a1d8f372cb4c5c0f20a12414d2dce3d507b1a625553d855"

  strings:
    $s1 = "_debug': False, " fullword ascii
    $s2 = "e, 'x_seq': None, 'f_seq': None,0" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}