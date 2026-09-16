rule Virus_Hijack_Gen_Trojan_ShellObject_fKX_aeBHSxm_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fKX@aeBHSxm_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2041372b0126ce05ce0efe14964b491cf035aadaac75263e22f1efd55a93edc7"

  strings:
    $s1 = "*IRE_OLSA_V120103_Def_V122304 Page 1 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}