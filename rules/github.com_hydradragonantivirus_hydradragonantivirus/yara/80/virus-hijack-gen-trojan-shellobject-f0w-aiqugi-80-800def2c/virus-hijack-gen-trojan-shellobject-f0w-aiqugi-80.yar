rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_80 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_80.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a2c7b053e324577784220007d11b7c5325d26636cdb7042b80747f956d96f1d6"

  strings:
    $s1 = "B4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}