rule Virus_Hijack_Trojan_Generic_35359124 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Generic.35359124.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e19363db82a105dabbc5f5f1680ae2fe711581fc803423d79d89175b09c87419"

  strings:
    $s1 = "cRab j@d" fullword ascii
    $s2 = "NakE(," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}