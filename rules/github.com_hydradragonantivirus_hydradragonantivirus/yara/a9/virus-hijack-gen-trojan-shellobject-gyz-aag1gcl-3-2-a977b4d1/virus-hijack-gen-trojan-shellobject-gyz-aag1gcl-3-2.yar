rule Virus_Hijack_Gen_Trojan_ShellObject_gyZ_aag1Gcl_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gyZ@aag1Gcl_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d135cf6cd05744a45857bf532054bb56e4a4c77152e81dbf3e329f4e0c61e53"

  strings:
    $s1 = "Microsoft Office Document Cache Migration" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}