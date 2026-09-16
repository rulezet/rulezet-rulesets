rule Virus_Hijack_Trojan_GenericKDZ_74550_25_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_25_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51c59d1ab82d5059b3a5b4b0c0f65db0772d64a047e1864a93be10b2f3c6baf7"

  strings:
    $s1 = "Snot?x<ww" fullword ascii
    $s2 = "Y(PlUP" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}