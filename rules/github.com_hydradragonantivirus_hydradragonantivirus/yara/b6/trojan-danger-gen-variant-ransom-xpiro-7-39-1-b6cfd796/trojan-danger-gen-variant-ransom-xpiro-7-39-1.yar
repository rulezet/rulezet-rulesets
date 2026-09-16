rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_39_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_39_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1fcb9d47bcc80dfd7bf9c35299af83ae030943ecd44075c8f308e4cf0be5d9b"

  strings:
    $s1 = "fSubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}