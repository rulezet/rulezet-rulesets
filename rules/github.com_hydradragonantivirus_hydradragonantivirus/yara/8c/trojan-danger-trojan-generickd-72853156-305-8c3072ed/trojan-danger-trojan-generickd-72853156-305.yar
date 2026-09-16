rule Trojan_Danger_Trojan_GenericKD_72853156_305 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_305.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "146164d554288ce438cf7719e6ac438b0a332cd510738b1aff3eaf290d1281f7"

  strings:
    $s1 = "V[TRap?<RRnu" fullword ascii
    $s2 = "V[TRap?<nau" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}