rule Virus_Danger_Gen_Trojan_ShellObject_PCZ_aSQ1jei_2 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.PCZ@aSQ1jei_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c73a1cc792d655f15d178e84cac5fefb83c115540dd6cfad35f64dbf8317269"

  strings:
    $s1 = "Uninstall Ruby 3.2.2-1-x64.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}