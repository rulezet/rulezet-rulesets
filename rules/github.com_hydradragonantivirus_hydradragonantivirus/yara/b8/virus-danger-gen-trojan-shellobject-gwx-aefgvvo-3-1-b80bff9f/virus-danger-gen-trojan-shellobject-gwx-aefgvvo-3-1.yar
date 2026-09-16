rule Virus_Danger_Gen_Trojan_ShellObject_gWX_aeFgVVo_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.gWX@aeFgVVo_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22a9c17f88d528cfde7938576c3da8011488efaf669799caad42e4b4b32d78ac"

  strings:
    $s1 = "Python Manuals.lnk.exe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}