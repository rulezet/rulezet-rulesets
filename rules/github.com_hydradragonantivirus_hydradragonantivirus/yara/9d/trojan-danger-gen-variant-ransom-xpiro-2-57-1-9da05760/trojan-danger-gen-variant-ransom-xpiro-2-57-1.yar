rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_57_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_57_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de12d98268923ce83d16010ae70abdac31d5b3f923f5809c57ed94d40c5f0f11"

  strings:
    $s1 = "vCallbackListToRpc: begin" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}