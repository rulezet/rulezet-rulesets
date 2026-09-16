rule Virus_Hijack_Dropped_Generic_MSIL_Bladabindi_D9844156_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Generic.MSIL.Bladabindi.D9844156_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a067c9cf9179eb14397cebd5243b93830ffdf39d5e2acd5c4e02066693623fc"

  strings:
    $s1 = "'Object dump comF" fullword ascii
    $s2 = "enough spa" fullword ascii
    $s3 = "number ~d!" fullword ascii
    $s4 = "MAGE: af" fullword ascii
    $s5 = "Char#LocaleInfoA" fullword ascii
    $s6 = "+(null" fullword ascii
    $s7 = "base >" fullword ascii
    $s8 = "(ck type." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}