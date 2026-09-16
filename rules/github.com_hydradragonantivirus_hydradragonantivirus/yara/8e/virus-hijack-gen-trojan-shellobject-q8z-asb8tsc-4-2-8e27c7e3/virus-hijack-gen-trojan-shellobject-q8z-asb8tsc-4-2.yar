rule Virus_Hijack_Gen_Trojan_ShellObject_q8Z_aSb8tSc_4_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aSb8tSc_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "545bd184fc497a06b83e72f0ca8673be5d6ec7ce9f8e7a890b009db39404ea65"

  strings:
    $s1 = "miCO>@4" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}