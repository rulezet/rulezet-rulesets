rule Trojan_Danger_Trojan_GenericKD_72677122_153_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_153_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55ff1a1d51c5a2eead87fc8d9d9827c6c6ce8ee50ff954e63b484881a0fbe324"

  strings:
    $s1 = "yAiR$5?(" fullword ascii
    $s2 = "#winE;atFw1." fullword ascii
    $s3 = "@f,(APEX" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}