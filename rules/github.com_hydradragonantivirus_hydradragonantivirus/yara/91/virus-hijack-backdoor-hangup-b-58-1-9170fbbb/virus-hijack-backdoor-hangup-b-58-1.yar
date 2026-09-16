rule Virus_Hijack_Backdoor_Hangup_B_58_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_58_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c95babb51ab2af584fdd605a683e8b286470e010d4ef30d7fd6222336e899b0"

  strings:
    $s1  = "[incorrect headz" fullword ascii
    $s2  = "ring,Data.DBXComm>.T" fullword ascii
    $s3  = "mparison<System." fullword ascii
    $s4  = "Author#y#E:#" fullword ascii
    $s5  = "Support`" fullword ascii
    $s6  = "TArray<System." fullword ascii
    $s7  = "(Header" fullword ascii
    $s8  = "y$Dark" fullword ascii
    $s9  = "{*Morphic" fullword ascii
    $s10 = "Basic(0" fullword ascii
    $s11 = "QueryI,face" fullword ascii
    $s12 = "Object@bF" fullword ascii
    $s13 = "BLINK \"" fullword ascii
    $s14 = "Direction!" fullword ascii
    $s15 = "List<Sy" fullword ascii
    $s16 = "Data!P" fullword ascii
    $s17 = "ct@8|K;Check*U q" fullword ascii
    $s18 = "cond?(" fullword ascii
    $s19 = "WHATSO#" fullword ascii
    $s20 = "Engine#+xUL" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}