rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_ayzr0Ib_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@ayzr0Ib_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5aa9febf85db737687a00bb0e2086bd0d501fbb8841f046ef43fc991458ebf38"

  strings:
    $s1 = "Dpurposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}