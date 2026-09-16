rule Virus_Hijack_Trojan_GenericKDZ_79663_94_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_94_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b13af846bb4be67d183f6e5375cc9ca171bc2e7a8a95b4c68228ebf197375648"

  strings:
    $s1 = "gIrO(_" fullword ascii
    $s2 = "-&%YONT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}