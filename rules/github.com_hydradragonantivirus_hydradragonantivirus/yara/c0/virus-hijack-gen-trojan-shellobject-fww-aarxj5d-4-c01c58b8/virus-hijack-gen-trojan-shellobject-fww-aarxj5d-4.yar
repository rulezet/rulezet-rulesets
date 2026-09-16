rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_aarXj5d_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@aarXj5d_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab2bf0df5d67c414f0552cd05e7c08dcaad9112150bbafc1a8d984d75214a3be"

  strings:
    $s1 = "^purposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}