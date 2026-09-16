rule Virus_Hijack_Gen_Trojan_ShellObject_eyY_a4uiSHo_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eyY@a4uiSHo_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30274cd8bf86d117e46da0bfec1f05f77c0d9f1c516f72b746ea239e1d392998"

  strings:
    $s1 = "ation error" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}