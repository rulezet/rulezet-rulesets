rule Virus_Danger_Gen_Trojan_ShellObject_h0Y_aGjJTmg_4 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.h0Y@aGjJTmg_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7616f41b515f638717be8d81f42fc156e6e14259e2a55dfb4e634b1d13e66a13"

  strings:
    $s1 = "bauthorized sources. Certain upgrades, support, and other services may be offered only to users of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}