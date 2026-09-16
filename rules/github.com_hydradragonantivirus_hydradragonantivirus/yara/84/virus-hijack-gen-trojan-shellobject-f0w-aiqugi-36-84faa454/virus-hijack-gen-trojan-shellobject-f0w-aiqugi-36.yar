rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_36 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_36.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a4a9007c47c73ddc37b9e91056eef6ed2aed15ba74a41ae0215d20f51244098"

  strings:
    $s1 = "E64. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}