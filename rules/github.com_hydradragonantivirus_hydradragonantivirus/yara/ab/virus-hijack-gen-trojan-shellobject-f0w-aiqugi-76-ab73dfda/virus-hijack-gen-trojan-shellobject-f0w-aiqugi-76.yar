rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_76 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_76.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afb2b4bda05f502c4398a525eac6f1c3c8dcf7b8d62f0d8674180c0a01e8db89"

  strings:
    $s1 = "h.4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}