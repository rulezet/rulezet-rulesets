rule Trojan_Danger_Trojan_GenericKD_72853156_518_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_518_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53e59c43d92f808b00ff09878c2d1d37c10079c23bec3177bd8ec12a9358a621"

  strings:
    $s1 = "ith SOAP" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}