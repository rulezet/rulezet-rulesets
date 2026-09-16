rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_82 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_82.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74a7bbcc286bc5b043bff2ae03b73a14110912758b4ec56428c3cf6e00c3498a"

  strings:
    $s1 = "z4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}