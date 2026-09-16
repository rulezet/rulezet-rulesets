rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_98 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_98.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0dc3b1ad2c44a979e3cc07176e1e02c5a2fbafbd0ba62b7fc328935b6e93b943"

  strings:
    $s1 = "R4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}