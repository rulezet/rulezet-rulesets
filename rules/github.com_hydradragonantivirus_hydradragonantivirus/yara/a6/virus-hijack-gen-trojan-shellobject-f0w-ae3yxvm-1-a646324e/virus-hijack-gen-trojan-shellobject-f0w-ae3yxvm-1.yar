rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_ae3yXvm_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@ae3yXvm_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08efb3152c463ff1327db7f46b503e249c968a90a9f955b45ab12bb9925b54f4"

  strings:
    $s1 = "/v4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}