rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_86 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_86.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65efc25c26dc3f12c163dd2af5c326d3725427b008f59901443750a578c2cf88"

  strings:
    $s1 = "N4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}