rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_ayzr0Ib_18 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@ayzr0Ib_18.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "77f9e6608b39106fea2fef2776c14c114be1120855efd92d83d70dfb705ae7b8"

  strings:
    $s1 = "-purposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}