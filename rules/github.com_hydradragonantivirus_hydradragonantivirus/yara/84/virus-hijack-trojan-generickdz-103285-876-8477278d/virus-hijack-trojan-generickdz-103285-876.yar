rule Virus_Hijack_Trojan_GenericKDZ_103285_876 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_876.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c85e3be394d52f1749f8671dc57b5cf69c0173e4b5a1beba0f3f36e6f3de5e89"

  strings:
    $s1 = "PLa neutral arbitrator, whose decision will be final except for a limited right of appeal under the Federal" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}