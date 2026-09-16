rule Virus_Hijack_Trojan_GenericKDZ_98388_50_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_50_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64c0f0e4025eea16268e6c20f62a92b6bb853ef2e4e944d8fa520ca3acfc20d6"

  strings:
    $s1 = "{s*mUmp" fullword ascii
    $s2 = "GP)SIsI" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}