rule Trojan_Autorun_Trojan_GenericKD_72517131_224_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_224_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e7cdf9548c7e7b0aadc5b13fb0391b943bf4a32b91c1d41f9fef1b2952222d2"

  strings:
    $s1 = "AUser, Marketing User, Manufacturing User, Purcha" fullword ascii
    $s2 = ":i@EYRA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}