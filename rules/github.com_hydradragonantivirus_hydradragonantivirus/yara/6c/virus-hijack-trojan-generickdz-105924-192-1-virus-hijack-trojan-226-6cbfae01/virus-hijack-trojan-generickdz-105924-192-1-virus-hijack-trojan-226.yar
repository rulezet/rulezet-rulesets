rule _Virus_Hijack_Trojan_GenericKDZ_105924_192_1_Virus_Hijack_Trojan_226 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Trojan.GenericKDZ.105924_192_1.vir, Virus.Hijack_Trojan.GenericKDZ.105924_205_1.vir, Virus.Hijack_Trojan.GenericKDZ.105924_211_1.vir, Virus.Hooker_Trojan.GenericKD.64731121_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3a4d992e292e1ab1ac286ba068b628968b11cae3d3830e2d4426fa911c6c11d"
    hash2       = "a68e1013a6e7861bcf58a8f933ee67f003f89b842c7f425cff9330e124813753"
    hash3       = "8bdbc65ae0a6aadb8fa7c794cdd132edc212aee7be8629710986e62a5e4c7dfe"
    hash4       = "bf6b57ff4efd90fcb7a9358ad977082028555ac9f26c37dd44b90f47a2fcc96f"

  strings:
    $s1  = "Hit test: %d - \"%s\"" fullword ascii
    $s2  = "Error in include file \"%s\" near line %d:" fullword ascii
    $s3  = "Error in main file near line %d: %s" fullword ascii
    $s4  = "Log Viewer %s for %s (%s)" fullword ascii
    $s5  = "GetFileSize failed. status 0x%x" fullword ascii
    $s6  = "Log Viewer %s for %s" fullword ascii
    $s7  = "Type \"%s\" already defined." fullword ascii
    $s8  = "Forward type definition could not be resolved: %s" fullword ascii
    $s9  = "OnNewLogFile Invalid checksum 0x%X. Expected 0x%X" fullword ascii
    $s10 = " -> [BAD BUFFER]" fullword ascii
    $s11 = "Cannot open the log file: \"%s\"" fullword ascii
    $s12 = "Base type \"%s\" unresolved for typedef \"%s\"." fullword ascii
    $s13 = "Undefined base type \"%s\" for alias." fullword ascii
    $s14 = "Unknown type \"%s\"." fullword ascii
    $s15 = "Failed to parse the manifest files" fullword ascii
    $s16 = "Failed to create the font" fullword ascii
    $s17 = "Failed to create the error brush" fullword ascii
    $s18 = "Undefined UIID \"%s\"." fullword ascii
    $s19 = "Could not parse the manifest files from \"%s\":" fullword ascii
    $s20 = " Using manifest files from: \"%s\"" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}