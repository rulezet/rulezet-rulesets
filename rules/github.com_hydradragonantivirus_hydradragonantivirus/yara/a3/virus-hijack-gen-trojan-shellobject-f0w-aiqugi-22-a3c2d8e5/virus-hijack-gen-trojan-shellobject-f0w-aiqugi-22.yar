rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_22 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_22.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "755f15b5909fc43440a032b3350b8ab668df98dc60f5a5c6ea191bbb3e70c3d7"

  strings:
    $s1 = "\\4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}