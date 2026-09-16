rule Virus_Hijack_Dropped_Trojan_Peed_Gen_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Trojan.Peed.Gen_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "048edff0b903ed4eb548320e29d62676fb6bc85f2eb5aa3bfc21dfb489896072"

  strings:
    $s1 = "WebToolBar component" fullword wide
    $s2 = "  is registered trademark of Kaspersky Lab ZAO." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}