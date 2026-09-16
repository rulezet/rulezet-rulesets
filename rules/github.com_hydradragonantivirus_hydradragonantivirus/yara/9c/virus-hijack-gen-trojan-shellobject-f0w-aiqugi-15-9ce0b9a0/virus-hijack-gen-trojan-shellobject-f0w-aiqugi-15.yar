rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_15 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_15.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3dfd3095164117cc716ed97c507283efde0d4728d258028edd7a6c07f0ac76e"

  strings:
    $s1 = "?4. Language Packs and Proofing Tools. If you acq" fullword ascii
    $s2 = "lImE}#;" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}