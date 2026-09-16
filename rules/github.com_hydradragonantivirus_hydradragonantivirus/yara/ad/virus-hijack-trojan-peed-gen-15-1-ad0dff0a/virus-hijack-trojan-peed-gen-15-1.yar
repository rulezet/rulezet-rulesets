rule Virus_Hijack_Trojan_Peed_Gen_15_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_15_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7d636a6aad10c5e34af9482270a1c2a90d031d133f7456f2ac12618da4d27d6"

  strings:
    $s1 = "J@sErO" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}