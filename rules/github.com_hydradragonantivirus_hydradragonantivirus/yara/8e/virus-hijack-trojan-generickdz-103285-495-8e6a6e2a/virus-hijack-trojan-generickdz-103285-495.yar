rule Virus_Hijack_Trojan_GenericKDZ_103285_495 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_495.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb9792e712be5c3096220289e1ac2e8f39cb740b8b31fa1389cdfd140f63b049"

  strings:
    $s1 = "~University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}