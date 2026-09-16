rule Virus_Hijack_Gen_Trojan_ShellObject_IuZ_aiy413e_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.IuZ@aiy413e_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb66030f327faa7f617800fe3cb8fd06c2ec39d5013f93e40efec6304ada45c7"

  strings:
    $s1 = "!Error Down" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}