rule Virus_Hijack_Trojan_GenericKDZ_105924_15_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_15_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40978905a7a978c2703728930de12d7339b439ead0bcbd8cb362c19653770c73"

  strings:
    $s1  = "# inflate 1." fullword ascii
    $s2  = "ed dictionary" fullword ascii
    $s3  = "8 Mark Adler L" fullword ascii
    $s4  = "&Shutdown)" fullword ascii
    $s5  = "insufXcijt memo" fullword ascii
    $s6  = "heRB`Ln" fullword ascii
    $s7  = "\\[lEek" fullword ascii
    $s8  = "KAiSER" fullword ascii
    $s9  = ">OnTO) " fullword ascii
    $s10 = "]8<mixY" fullword ascii
    $s11 = "make L" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}