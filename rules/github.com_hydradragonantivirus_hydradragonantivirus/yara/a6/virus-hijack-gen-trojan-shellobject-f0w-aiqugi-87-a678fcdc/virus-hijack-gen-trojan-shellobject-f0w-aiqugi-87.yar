rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_87 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_87.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81ea4ae0648bf1eb8f6ffc47d4860e734056e1aaf40ad44b87959501125b2c76"

  strings:
    $s1 = "'4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}