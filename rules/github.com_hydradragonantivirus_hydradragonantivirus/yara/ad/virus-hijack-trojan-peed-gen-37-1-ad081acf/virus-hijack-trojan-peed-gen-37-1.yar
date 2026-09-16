rule Virus_Hijack_Trojan_Peed_Gen_37_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_37_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "120460c8a8555145c70de7855daa15d0a1d3d941a1d9a35398e6eadf727194ca"

  strings:
    $s1 = "<SelL;" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}