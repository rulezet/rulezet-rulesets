rule Virus_Danger_Trojan_GenericKDZ_103285_22 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Trojan.GenericKDZ.103285_22.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9fb2a8469ef927e85ccda56bc26154888c537ef0ffbacf4509e0831d14141f0"

  strings:
    $s1 = "toThis agreement is governed by the substantive and procedural laws of Ireland without reference to its conflictof laws principl" ascii
    $s2 = "toThis agreement is governed by the substantive and procedural laws of Ireland without reference to its conflictof laws principl" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}