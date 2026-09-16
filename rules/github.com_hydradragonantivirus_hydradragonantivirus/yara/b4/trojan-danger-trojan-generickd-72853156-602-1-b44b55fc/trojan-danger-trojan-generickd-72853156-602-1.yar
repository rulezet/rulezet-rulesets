rule Trojan_Danger_Trojan_GenericKD_72853156_602_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_602_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b8966c8d298caea862cedcd93796a61390dd84ee2ef514d115d09a61d92b73c"

  strings:
    $s1 = " Leviathan 2008" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}