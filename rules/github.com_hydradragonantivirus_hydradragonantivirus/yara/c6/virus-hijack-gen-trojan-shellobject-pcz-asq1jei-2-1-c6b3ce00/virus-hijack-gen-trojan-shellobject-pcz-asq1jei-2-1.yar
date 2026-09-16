rule Virus_Hijack_Gen_Trojan_ShellObject_PCZ_aSQ1jei_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.PCZ@aSQ1jei_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9965958d763005cb27c47fa0610df8658dbca84b9f5675487fe5f48198d332fe"

  strings:
    $s1 = "rive}S?" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}