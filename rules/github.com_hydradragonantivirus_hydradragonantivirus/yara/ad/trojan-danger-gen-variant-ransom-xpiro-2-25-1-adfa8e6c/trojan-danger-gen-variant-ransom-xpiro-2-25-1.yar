rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_25_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_25_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96b0185fb8bc95f001221af58eb9a06fb6de11f00dc2dfa5c876a5f5a007f9a4"

  strings:
    $s1 = "Vyou received the software, and also any Microsoft updates, supplements, and services for the software," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}