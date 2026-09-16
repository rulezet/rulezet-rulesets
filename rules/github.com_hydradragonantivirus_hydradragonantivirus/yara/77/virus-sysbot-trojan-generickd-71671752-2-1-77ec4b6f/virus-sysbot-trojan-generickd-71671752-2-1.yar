rule Virus_Sysbot_Trojan_GenericKD_71671752_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.GenericKD.71671752_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01ea9d1c8d81082aed91cf10e695f0522c71118dc3f67a9d598a967d17b9846c"

  strings:
    $s1 = "/\"ScUr" fullword ascii
    $s2 = "[boNED" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}