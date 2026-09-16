rule Virus_Infector_GenPack_Generic_Adware_Gator_A_E630C5E7_12 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_GenPack.Generic.Adware.Gator.A.E630C5E7_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7b62f4f7eb0e2be0b9f901d6815e8fdd8ef1b805ef4d57092f90385e92dcedc"

  strings:
    $s1 = "g Condition in IEC61966-2.1" fullword ascii
    $s2 = ",Reference Viewi" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}