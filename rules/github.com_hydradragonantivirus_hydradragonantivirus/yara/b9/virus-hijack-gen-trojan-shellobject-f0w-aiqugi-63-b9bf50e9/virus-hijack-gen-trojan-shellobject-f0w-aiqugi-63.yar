rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_63 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_63.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a26dcfa0b3487d492da2514c0df4e0da4113d2d09ac7d19d3df6817821e3976d"

  strings:
    $s1 = "`4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}