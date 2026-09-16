rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_ayzr0Ib_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@ayzr0Ib_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46e1f82055ff023c4b03e2b58674077b3f1606584b9159249dbe2d1c387229bd"

  strings:
    $s1 = "6|purposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}