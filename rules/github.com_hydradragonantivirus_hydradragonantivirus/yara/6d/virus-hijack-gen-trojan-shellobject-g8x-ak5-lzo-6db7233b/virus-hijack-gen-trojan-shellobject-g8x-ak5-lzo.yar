rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aK5_lZo {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aK5!lZo.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2639f1518ac3900b37e1561e3aff1a1cf1354a2f540115d6671fdb352fa1f8a8"

  strings:
    $s1 = "?University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}