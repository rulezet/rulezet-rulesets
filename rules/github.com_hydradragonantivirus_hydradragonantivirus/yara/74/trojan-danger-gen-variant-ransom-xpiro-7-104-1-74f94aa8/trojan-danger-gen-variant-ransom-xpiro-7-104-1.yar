rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_104_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_104_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e2ac3ea09adba39f154cb328a8d9efa5f6ec3c2e7aa08751bd9bef8685838fa"

  strings:
    $s1 = "/available at go.microsoft.com/fwlink/?linkid=245497 to the AAA. You agree to commence arbitration only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}