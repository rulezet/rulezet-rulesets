rule Virus_Danger_Gen_Trojan_ShellObject_PCZ_aqns23l_1 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.PCZ@aqns23l_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a35d348ccb95903b462a8a95b2c2131ef904d7b98ed99e3435b99aeb910c1e1d"

  strings:
    $s1 = "Compile Script to .exe (x64).lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}