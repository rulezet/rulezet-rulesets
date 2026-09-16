rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aeOesjp_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aeOesjp_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3278c004d38d9aabd94973e48dd0f9bbd7f25f1135a5ef978dfc0cbc2dc8169e"

  strings:
    $s1  = "%s%u, %u Processor(s)" fullword ascii
    $s2  = "FAAD2 is available at http://www.audiocoding.com" fullword ascii
    $s3  = "Usage: %s <old root> <new root> <file> [<old_oldrootlen>]" fullword ascii
    $s4  = " libpng version 1.2.29 - May 8, 2008" fullword ascii
    $s5  = "Error getting decoder for %s" fullword ascii
    $s6  = "@Borland C++ - Copyright 1999 Inprise Corporation" fullword ascii
    $s7  = "Borland C++ - Copyright 2002 Borland" fullword ascii
    $s8  = "Error getting decoder." fullword ascii
    $s9  = "Failed to create tmp file %s." fullword ascii
    $s10 = "Scanned %d file%s in %ld sec" fullword ascii
    $s11 = "UNIDENTIFIED DLL" fullword ascii
    $s12 = "Error getting sha1 for %s" fullword ascii
    $s13 = "companion shared " fullword wide
    $s14 = "Ignoring attempt to set all-zero chromaticity values" fullword ascii
    $s15 = "AACTagReader can only process a single track per file." fullword ascii
    $s16 = "@The %s executable launcher was unable to locate its " fullword wide
    $s17 = "Failed to fix file %s (internal error)." fullword ascii
    $s18 = "Error flushing to %s ?!" fullword ascii
    $s19 = "Failed to update file %s (internal error)." fullword ascii
    $s20 = "AACTagReader (Version 0.4)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}