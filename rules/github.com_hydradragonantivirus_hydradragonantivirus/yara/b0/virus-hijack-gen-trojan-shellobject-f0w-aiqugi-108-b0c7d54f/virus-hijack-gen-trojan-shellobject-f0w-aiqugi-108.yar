rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_108 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_108.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3b4c78995d66e2f0450921ab95f468b2cfed8dcb96b130966547662abc8e8a7"

  strings:
    $s1 = "$4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}