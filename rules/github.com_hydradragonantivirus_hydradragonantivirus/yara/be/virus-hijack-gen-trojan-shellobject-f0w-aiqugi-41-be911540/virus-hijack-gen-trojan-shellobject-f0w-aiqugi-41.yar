rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_41 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_41.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "130b7663a90527e8d318cc677c94f69d0a871349a36e9df43e00c4ac98fe0d6d"

  strings:
    $s1 = "/4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}