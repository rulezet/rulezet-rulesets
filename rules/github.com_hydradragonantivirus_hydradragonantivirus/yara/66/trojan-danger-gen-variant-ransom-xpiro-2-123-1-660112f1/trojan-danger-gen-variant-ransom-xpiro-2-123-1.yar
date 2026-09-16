rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_123_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_123_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43a4c3d58d32732a8accc245d6d3ee55b76e433904c7314c5ca4b22909ef344f"

  strings:
    $s1 = "<xorders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}