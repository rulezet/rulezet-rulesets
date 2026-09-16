rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_102 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_102.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cce09b02363f524e7257516df94b38fcec7d76e4a5da68c4faa58f0821caefdb"

  strings:
    $s1 = "%4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}