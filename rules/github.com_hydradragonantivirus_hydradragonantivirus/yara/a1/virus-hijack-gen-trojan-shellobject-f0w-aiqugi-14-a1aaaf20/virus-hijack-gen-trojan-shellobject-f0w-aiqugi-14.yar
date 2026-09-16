rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_14 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_14.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4435adff66e4cb604c598351db50ee57c61b9fafedbaed1fb304cd68d7bbd4ae"

  strings:
    $s1 = ":4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}