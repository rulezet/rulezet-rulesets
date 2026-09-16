rule Trojan_Danger_Trojan_GenericKD_72853156_365 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_365.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4aa0350cc15c13a82cdeb812bd7087accf8bbc0bdc00291f07361e844e6f73e"

  strings:
    $s1 = "Ruby 3.2.2 API Reference.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}