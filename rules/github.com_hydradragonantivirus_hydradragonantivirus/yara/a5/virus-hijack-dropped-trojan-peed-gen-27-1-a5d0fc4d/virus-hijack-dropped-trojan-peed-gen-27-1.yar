rule Virus_Hijack_Dropped_Trojan_Peed_Gen_27_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Trojan.Peed.Gen_27_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68ef561c5c622b23639013d7cb3991e697f1e0878a5329c4961090218eb5bd5d"

  strings:
    $s1 = "n6:9f;6jl>BAnC>rtFJIvKFz|NRQ~SN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}