rule Virus_Danger_Gen_Trojan_ShellObject_eSW_amMcCQb_1 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.eSW@amMcCQb_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "595b8722d600b929b1687d19470b1408bd9d259dd489b47e3d19a04f03a8eb65"

  strings:
    $s1 = "lnwhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}