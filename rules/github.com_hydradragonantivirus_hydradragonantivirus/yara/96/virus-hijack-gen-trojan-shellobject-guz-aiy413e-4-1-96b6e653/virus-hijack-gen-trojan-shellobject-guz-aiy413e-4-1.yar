rule Virus_Hijack_Gen_Trojan_ShellObject_GuZ_aiy413e_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.GuZ@aiy413e_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7cc3275a7251db7f626a96a4e902ecd1ef7c7af542364d864599ae88961ca41"

  strings:
    $s1 = "Aphasic" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}