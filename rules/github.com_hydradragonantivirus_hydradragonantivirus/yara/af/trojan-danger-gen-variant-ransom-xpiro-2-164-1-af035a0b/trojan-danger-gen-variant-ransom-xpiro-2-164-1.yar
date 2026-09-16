rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_164_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_164_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f924da766dec54773c28a7c528f8aa0481458918bfa695dbd53ae93bfc2b2da0"

  strings:
    $s1 = "Multiple purchase lines may be created on either a requisition or purchase order or may be a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}