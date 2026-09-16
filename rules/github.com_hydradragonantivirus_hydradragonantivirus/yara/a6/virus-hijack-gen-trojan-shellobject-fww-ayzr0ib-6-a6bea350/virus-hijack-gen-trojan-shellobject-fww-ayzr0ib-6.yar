rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_ayzr0Ib_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@ayzr0Ib_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71b31fca6e2261f670c15ef3f4d933a721391fd58c2e4d27e7675060cfa849f7"

  strings:
    $s1 = "hpurposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}