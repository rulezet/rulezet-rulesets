rule Virus_Hijack_Gen_Trojan_ShellObject_p8W_aCNb4Uo_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.p8W@aCNb4Uo_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be406ace2142cda76ff607d322da039459199ba9b0d13cb895013d7fabe45bac"

  strings:
    $s1 = "$AhnLab V3 Lite 3." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}