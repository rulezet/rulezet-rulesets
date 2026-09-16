rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_18 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_18.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd482dde12487de3dbec155089530c776595d6fcdd66b2875571e65d23f18742"

  strings:
    $s1 = "44. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}