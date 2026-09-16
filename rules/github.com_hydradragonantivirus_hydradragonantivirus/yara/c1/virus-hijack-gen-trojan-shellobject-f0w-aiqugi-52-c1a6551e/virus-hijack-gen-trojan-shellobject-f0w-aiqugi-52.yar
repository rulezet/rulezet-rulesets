rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_52 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_52.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dfcf516cae2237dd983b31c2e41609f1ca9015b8ec1f077569089a93c3a151ec"

  strings:
    $s1 = "c4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}