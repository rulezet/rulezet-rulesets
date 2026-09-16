rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_59 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_59.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e90269e45d52a6cf77453119d98993989dc188c5b9e5fc42ff3d4f10cfe11512"

  strings:
    $s1 = "\"14. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}