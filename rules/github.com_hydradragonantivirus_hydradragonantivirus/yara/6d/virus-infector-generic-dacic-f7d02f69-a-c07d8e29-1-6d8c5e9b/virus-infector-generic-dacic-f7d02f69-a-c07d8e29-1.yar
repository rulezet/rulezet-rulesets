rule Virus_Infector_Generic_Dacic_F7D02F69_A_C07D8E29_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Generic.Dacic.F7D02F69.A.C07D8E29_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b75f14a41f93aaecc17258bdd8c53ff4a8023e403a0b4fb9531c1a1e8dbe53e6"

  strings:
    $s1 = "g Condition in IEC61966-2.1" fullword ascii
    $s2 = ",Reference Viewi" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}