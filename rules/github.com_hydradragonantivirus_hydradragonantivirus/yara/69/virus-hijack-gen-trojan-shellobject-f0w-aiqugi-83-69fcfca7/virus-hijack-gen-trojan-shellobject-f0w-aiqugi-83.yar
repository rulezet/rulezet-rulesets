rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_83 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_83.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c8bd98126cac26bb696e3bcbf3462a243b6b516bdd0e78a38c047d8ce3464d7"

  strings:
    $s1 = "n4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}