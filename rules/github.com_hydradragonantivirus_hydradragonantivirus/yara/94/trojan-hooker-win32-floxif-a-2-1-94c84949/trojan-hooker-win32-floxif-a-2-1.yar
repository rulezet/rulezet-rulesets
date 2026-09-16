rule Trojan_Hooker_Win32_Floxif_A_2_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "13b486f443ea705c2bef314ab9448eed24a8503c72f765c38a4d69de33401bf6"

  strings:
    $s1 = "opacate" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}