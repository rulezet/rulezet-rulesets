rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_95 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_95.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f219367461a4fb834485b634c87ac647a2f8600a61225d788a2fed3370ef5cf4"

  strings:
    $s1 = ".4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}