rule Virus_Danger_Gen_Trojan_ShellObject_fWW_ayzr0Ib_1 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.fWW@ayzr0Ib_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "154addc703f2eec6d440d253a8311ec118fddf05da794c10171a05b28f6e3316"

  strings:
    $s1 = "'purposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}