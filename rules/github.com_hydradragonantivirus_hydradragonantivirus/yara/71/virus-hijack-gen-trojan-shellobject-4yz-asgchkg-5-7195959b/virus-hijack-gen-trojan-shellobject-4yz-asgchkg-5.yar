rule Virus_Hijack_Gen_Trojan_ShellObject_4yZ_aSgChKg_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.4yZ@aSgChKg_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "477860dd763d09977738131c23a3f932b70b3b2a9618c8a84996688a12ffc9ff"

  strings:
    $s1 = "Wj[]Qq]PAlL]" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}