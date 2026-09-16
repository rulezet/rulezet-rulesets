rule Trojan_Danger_Trojan_GenericKD_72597336_10_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72597336_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53578fe7a51eabc65025bae8b8bbe279d6f9e2ca79c21862e3e0b3259e50052b"

  strings:
    $s1 = "{dispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}