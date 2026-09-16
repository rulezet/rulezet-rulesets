rule Virus_Danger_Gen_Trojan_ShellObject_h0Y_aGjJTmg_3 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.h0Y@aGjJTmg_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ff60520eb5a724e0f16d5e298bd79bfb50b714687d5f9e5ba5d6cb432d34fd1"

  strings:
    $s1 = "*authorized sources. Certain upgrades, support, and other services may be offered only to users of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}