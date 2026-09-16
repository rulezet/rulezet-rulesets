rule Virus_Injector_Win32_Worm_Viking_NDL_3 {
  meta:
    description = "datamaliciousorder - file Virus.Injector_Win32.Worm.Viking.NDL_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9fc4af8b4534a889d9fbc0b0778608989ad1b893e4e4f681192abecf989c508"

  strings:
    $s1  = "Script Error Dialog - Width" fullword ascii
    $s2  = "Script Error Dialog - Height" fullword ascii
    $s3  = ";Couldn't dump thread: %s" fullword ascii
    $s4  = "Configure Controls - Scroll Position - Import Manager" fullword ascii
    $s5  = "*** Failed to get attributes for redist directory, " fullword ascii
    $s6  = "Variables Dialog - Initial Value Column Width" fullword ascii
    $s7  = "Error reading target translation keys in camera section." fullword ascii
    $s8  = "Variables Dialog - Name Column Width" fullword ascii
    $s9  = "Variables Dialog - Type Column Width" fullword ascii
    $s10 = "%sMem - Undo: %d, Clip: %d, Tot: %d, OS: %d" fullword ascii
    $s11 = "Variables Dialog - Height" fullword ascii
    $s12 = "Random Groups Dialog - Height" fullword ascii
    $s13 = "Import Manager Column Width - Type" fullword ascii
    $s14 = "Import Manager Column Width - Path" fullword ascii
    $s15 = "Random Groups Dialog - Width" fullword ascii
    $s16 = "Configure Controls - Scroll Position - Sound Editor" fullword ascii
    $s17 = "Configure Controls - Scroll Position - AI Editor" fullword ascii
    $s18 = "Configure Controls - Scroll Position - Object Manager" fullword ascii
    $s19 = "Import Manager Column Width - Name" fullword ascii
    $s20 = "(%s//%d) Error, couldn't find string template \"%s\"" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}