rule Virus_Hijack_Trojan_GenericKDZ_74550_152_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_152_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e0d39b2ff8a6018029cc8f6114b13f0319deef91a3a8fd9dffccfbcd2ed974a"

  strings:
    $s1 = "}a(aUGe" fullword ascii
    $s2 = "I(FUci" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}