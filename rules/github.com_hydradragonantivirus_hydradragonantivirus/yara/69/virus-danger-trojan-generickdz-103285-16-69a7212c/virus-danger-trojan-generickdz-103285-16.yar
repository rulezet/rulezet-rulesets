rule Virus_Danger_Trojan_GenericKDZ_103285_16 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Trojan.GenericKDZ.103285_16.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d5e98750e7c5853fa1d2cf58781084b1577d62fceb44ffc86c40c4f4d590bda"

  strings:
    $s1 = "9purposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}