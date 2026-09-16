rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_268 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_268.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ddc66527393b9125c9209a3d7f16e0887450bb3ef9a364ad7352cfd6141667fe"

  strings:
    $s1 = "V[TRap?<RRnu" fullword ascii
    $s2 = "V[TRap?<nau" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}