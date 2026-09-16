rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_53 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_53.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70a9d397f463b61a1f2c8fe826adefb6d40fd46f1eb8ad97333ae1ae12d57f31"

  strings:
    $s1 = "l4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}