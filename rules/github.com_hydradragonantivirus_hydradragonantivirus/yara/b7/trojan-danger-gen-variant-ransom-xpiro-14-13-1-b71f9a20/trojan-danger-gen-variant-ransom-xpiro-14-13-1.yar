rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_14_13_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.14_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "555654c11ddfd2a7c2bf63f28fefe4b91539f29db3a5e3eaa1d7f8ce032c3f88"

  strings:
    $s1 = "@cautomatically sign you into the software using the same Microsoft account. This allows you to store and" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}