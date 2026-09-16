rule Virus_Hijack_Trojan_GenericKDZ_103285_308 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_308.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e3c32f1b3929c2d4733581ee69c53d545d27527ce4aebdc1f5f984bb1105ee9"

  strings:
    $s1 = "A3University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}