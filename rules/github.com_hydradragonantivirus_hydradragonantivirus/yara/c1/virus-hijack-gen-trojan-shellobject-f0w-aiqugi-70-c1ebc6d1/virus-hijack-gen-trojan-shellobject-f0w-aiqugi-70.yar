rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_70 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_70.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ebd65e260d42990060b45a2203d3b40cf6075c0fe9ce0a42e34b53dcb6cc106c"

  strings:
    $s1 = "c4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}