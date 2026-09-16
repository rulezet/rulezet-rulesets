rule Virus_Hijack_Gen_Trojan_ShellObject_fKX_aeBHSxm_14 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fKX@aeBHSxm_14.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17f0892f0c409554714d73e9a9c01ddf6055e3a5fd17953068d79739e6e19c19"

  strings:
    $s1 = "%<IRE_OLSA_V120103_Def_V122304 Page 1 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}