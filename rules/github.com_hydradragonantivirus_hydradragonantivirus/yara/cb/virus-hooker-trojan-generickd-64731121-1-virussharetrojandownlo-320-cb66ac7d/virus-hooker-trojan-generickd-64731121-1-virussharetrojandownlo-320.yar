import "pe"
rule _Virus_Hooker_Trojan_GenericKD_64731121_1_VirusShareTrojanDownLo_320 {
  meta:
    description = "datamaliciousorder - from files Virus.Hooker_Trojan.GenericKD.64731121_1.vir, VirusShareTrojanDownLoader2255152_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf6b57ff4efd90fcb7a9358ad977082028555ac9f26c37dd44b90f47a2fcc96f"
    hash2       = "38f8d343ce34042540ebb4803a134082aae6c4265188f2d077d046fec8174f1f"

  strings:
    $s1  = "ReadProcessMemory (%p for %d) failed with winerror %u (bytes read: %d)" fullword ascii
    $s2  = "Process %u opened handle=%d." fullword ascii
    $s3  = "*- - - - - - - - - - Heap %IX Hogs - - - - - - - - - -" fullword ascii
    $s4  = "*- - - - - - - - - - Start of data for heap @ %IX - - - - - - - - - -" fullword ascii
    $s5  = "GetVersionInfoEx() failed with error %u" fullword ascii
    $s6  = "*- - - - - - - - - - End of data for heap @ %IX - - - - - - - - - -" fullword ascii
    $s7  = "Failed to load symbols for %s (%x)." fullword ascii
    $s8  = "Failed to open output file `%s'" fullword ascii
    $s9  = "OpenThread failed with error : %ld" fullword ascii
    $s10 = "Umdh does not run on systems older than 4.0" fullword ascii
    $s11 = "CreateToolhelp32Snapshot failed with error : %ld" fullword ascii
    $s12 = "Umdh OS version %u.%u" fullword ascii
    $s13 = "Unexpected argument \"%s\"" fullword ascii
    $s14 = "Cannot run umdh for OS version %u.%u on a %u.%u system" fullword ascii
    $s15 = "Can't open %s for reading." fullword ascii
    $s16 = "     UMDH VERSION %s                                                           " fullword ascii
    $s17 = "_NT_SYMBOL_PATH set by default to %s" fullword ascii
    $s18 = "DT!Rich" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "aae410db5a351d384de2e35faf59497e" and (8 of them)
    ) or (all of them)
}