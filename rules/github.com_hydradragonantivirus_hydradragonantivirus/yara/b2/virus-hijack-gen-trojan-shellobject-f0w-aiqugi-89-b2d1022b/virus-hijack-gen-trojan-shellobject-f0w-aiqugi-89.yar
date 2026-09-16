rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_89 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_89.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d038212629cbc2e67ca93ed66c8c59a3b9bf9c672b2ddf9e6a0575f3e71f153a"

  strings:
    $s1 = "{\"4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}