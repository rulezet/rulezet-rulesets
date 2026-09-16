rule Trojan_Danger_Trojan_GenericKD_72853156_603_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_603_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "250f1433d2ce995f333d251c6541f8ad708b831a7828c74003803e86414744a5"

  strings:
    $s1 = " Leviathan 2008" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}