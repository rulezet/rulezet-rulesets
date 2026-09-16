rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_23 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_23.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "917331e04eb89d5bc6a0ef710eff1e11387c725012081d0017ba68ef81b0e0d6"

  strings:
    $s1 = "(4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}