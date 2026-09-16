import "pe"
rule _Virus_Hijack_Trojan_GenericKDZ_105924_192_1_Virus_Hijack_Trojan_79 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Trojan.GenericKDZ.105924_192_1.vir, Virus.Hijack_Trojan.GenericKDZ.105924_224_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3a4d992e292e1ab1ac286ba068b628968b11cae3d3830e2d4426fa911c6c11d"
    hash2       = "ddc4fdef6b53eef42d57a6d8a2981011810cefcd682d8dba0775e821b94b3699"

  strings:
    $s1  = "Audio Control Processing Unit Descriptor:" fullword wide
    $s2  = "(Dynamic Range Compressor Process)" fullword wide
    $s3  = "Dumpries Company Limited" fullword wide
    $s4  = "Audio Control Interface Header Descriptor:" fullword wide
    $s5  = "(Undefined Process)" fullword wide
    $s6  = "(Up / Down Mix Process)" fullword wide
    $s7  = "(Dolby Prologic Process)" fullword wide
    $s8  = "(3D-Stereo Extender Process)" fullword wide
    $s9  = "(Reverberation Process)" fullword wide
    $s10 = "(Chorus Process)" fullword wide
    $s11 = "Process Specific:" fullword wide
    $s12 = "HCL Technologies India Private Limited" fullword wide
    $s13 = "Surecom Technology Corp." fullword wide
    $s14 = "Compeye Corporation" fullword wide
    $s15 = "Configuration Descriptor:" fullword wide
    $s16 = "Audio Control Input Terminal Descriptor:" fullword wide
    $s17 = "Audio Control Output Terminal Descriptor:" fullword wide
    $s18 = "Audio Control Mixer Unit Descriptor:" fullword wide
    $s19 = "Audio Control Selector Unit Descriptor:" fullword wide
    $s20 = "Audio Control Feature Unit Descriptor:" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "c4998075f1324ce0f644f12a548d76b1" and (8 of them)
    ) or (all of them)
}