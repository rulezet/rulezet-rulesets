rule Virus_Autorun_Trojan_GenericKDZ_94942_8 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Trojan.GenericKDZ.94942_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c86059952e1b8efbba92999a5ad6d366c7a42fd2cc969cf62828ddf37f3dbc66"

  strings:
    $s1 = "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.34.31938" fullword wide
    $s2 = "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.34.3193" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}