rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_85_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_85_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a27869212312994414a9052a6a5206fbe06bf66386d28c41bd4709755c80d62"

  strings:
    $s1 = "aAmust be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}