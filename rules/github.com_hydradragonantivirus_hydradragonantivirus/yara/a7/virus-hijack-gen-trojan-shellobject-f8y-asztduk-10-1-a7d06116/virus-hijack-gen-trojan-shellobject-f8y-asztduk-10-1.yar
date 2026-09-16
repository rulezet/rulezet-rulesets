rule Virus_Hijack_Gen_Trojan_ShellObject_f8Y_aSZtDuk_10_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aSZtDuk_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6e02b292d1c99a0286188d30b2e8b80558834d58ead900aadd268b40f14cd27"

  strings:
    $s1 = "*,Rich" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}