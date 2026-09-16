rule Trojan_Danger_Trojan_GenericKD_72677122_181_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_181_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d8cfb96f1b6d7a5fe603c40b70ac676b5bebff02d30db35ea15bc31ac079c21"

  strings:
    $s1 = "<AMOK`" fullword ascii
    $s2 = "5;lAKE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}