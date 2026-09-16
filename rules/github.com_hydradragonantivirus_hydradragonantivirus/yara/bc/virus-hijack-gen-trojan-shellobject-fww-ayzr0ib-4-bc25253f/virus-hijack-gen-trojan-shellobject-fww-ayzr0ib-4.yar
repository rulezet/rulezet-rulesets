rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_ayzr0Ib_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@ayzr0Ib_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "750cbd9e4c7bc0e6d6efc65b994e16d25b641acec1002774847e0aa4f3bf85ef"

  strings:
    $s1 = "t:purposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}