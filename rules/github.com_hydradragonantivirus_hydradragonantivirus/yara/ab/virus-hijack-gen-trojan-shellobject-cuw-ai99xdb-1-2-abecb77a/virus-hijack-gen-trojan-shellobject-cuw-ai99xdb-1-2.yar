rule Virus_Hijack_Gen_Trojan_ShellObject_cuW_ai99xDb_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.cuW@ai99xDb_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f40a37565e42d702849cb5f8fa3186698b445a70e1313a89d4e974d28a309bb4"

  strings:
    $s1 = "*sTUm?" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}