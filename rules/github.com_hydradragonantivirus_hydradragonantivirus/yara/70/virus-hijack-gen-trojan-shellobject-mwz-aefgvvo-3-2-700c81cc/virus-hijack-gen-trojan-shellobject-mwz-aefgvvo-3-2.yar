rule Virus_Hijack_Gen_Trojan_ShellObject_mWZ_aeFgVVo_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.mWZ@aeFgVVo_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7d8a6f548c20c94cb8d2113a91c5d736950a42d719ad270faa30fb7e476801e"

  strings:
    $s1 = "Rich*/" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}