rule Trojan_Autorun_Trojan_Ransom_Doboc_A_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.Ransom.Doboc.A_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68d86f0589b90cb4eeee3f984f901bb54136b0ea2f29cdc2d4b3c641be6912eb"

  strings:
    $s1 = "\"}quAd" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}