rule Virus_Hijack_Gen_Trojan_ShellObject_CyZ_ayMBdto_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.CyZ@ayMBdto_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27d4844c7f4e733f6089adea162de1b25a11ff583383c43debc6e11b118d09ba"

  strings:
    $s1 = "rEcCy?_" fullword ascii
    $s2 = "b*%roam" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}