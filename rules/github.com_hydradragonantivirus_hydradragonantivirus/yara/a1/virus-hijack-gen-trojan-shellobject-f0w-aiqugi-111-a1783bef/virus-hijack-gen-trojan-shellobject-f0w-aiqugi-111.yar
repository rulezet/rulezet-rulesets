rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_111 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_111.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89fe0a7a53d91c66e3906b6f9c23f6396ea8f846a30727cc081e841c7867bd38"

  strings:
    $s1 = "L>4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}