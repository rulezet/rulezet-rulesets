rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aian2n_45_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_45_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "370c78ecd539292a20e84dd4f58aaf5194a3b0db5ea857adfd46b50d6333426a"

  strings:
    $s1  = "Unable to load nhdefkey.dll" fullword ascii
    $s2  = "Unable to load nhraykey.dll" fullword ascii
    $s3  = "Unable to load user32.dll" fullword ascii
    $s4  = "Ecch - that must have been poisonous!" fullword ascii
    $s5  = "One common cause of this error is attempting to execute" fullword ascii
    $s6  = "Usage: %s -s [-v] <playertypes> [maxrank] [playernames]" fullword ascii
    $s7  = "hitum_cleave: unknown target direction [%d,%d,%d]?" fullword ascii
    $s8  = "stepping on poison spikes" fullword ascii
    $s9  = "Reserved menu command key '%s'" fullword ascii
    $s10 = "magic (%d) attempted on door." fullword ascii
    $s11 = "Long description of the game and commands." fullword ascii
    $s12 = "Execute debug breakpoint wizard?" fullword ascii
    $s13 = "tribute file error: bad %% command, line %d." fullword ascii
    $s14 = "Unknown key binding command '%s'" fullword ascii
    $s15 = "Use '%s' to toggle menu listing for possible targets." fullword ascii
    $s16 = "To report this error, contact %s%s" fullword ascii
    $s17 = "%s %s no longer poisoned." fullword ascii
    $s18 = "%s like %s might have been poisoned.  %s" fullword ascii
    $s19 = "like an evil coward for using a poisoned weapon." fullword ascii
    $s20 = "The blood floods the altar, which vanishes in %s cloud!" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}