rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_114 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_114.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95f56b5ad2db8c9fb7c13e4b843ebdbb8cc3f082d2ea6ad174d7a788781e8635"

  strings:
    $s1 = "w4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}