rule _Trojan_Autorun_Trojan_GenericKD_72869045_Virus_Hijack_Gen_Troja_92 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Trojan.GenericKD.72869045.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_15_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_2_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b4d08c1939546a758d6fe9b1b5284dc628aff3fef3cb798a4e535143a008a56"
    hash2       = "6eca375518c871cbafa55bb8b3f323c5138a90fe23a2590be889548e4186ae0c"
    hash3       = "66d0faa4052007cff3969e3b850cf218a17f7cc2a1282c9c956e0402fcfc35e6"
    hash4       = "1300abe8989a2b3b5e1ab0102c4decd1bb1035a73bacbe2b00a064fb74207f7b"

  strings:
    $s1  = "Assertion Failed: m_pGroup->Group.GroupInfo[nGroupIndex].ActiveProcessorMask == ( UINT64_MAX >> ( 64 - m_pGroup->Group.GroupInfo" ascii
    $s2  = "Assertion Failed: m_pGroup->Group.GroupInfo[nGroupIndex].ActiveProcessorMask == ( UINT64_MAX >> ( 64 - m_pGroup->Group.GroupInfo" ascii
    $s3  = "Setup script executed." fullword ascii
    $s4  = "Failed to start temp bootstrapper" fullword ascii
    $s5  = "Assertion Failed: 1 == nLogProcsPerPkg" fullword ascii
    $s6  = "Could not set the supported types for event log source." fullword ascii
    $s7  = "Could not create the registry key for event log source: gle: %u" fullword ascii
    $s8  = "Assertion Failed: pIterData < m_pGlpiExData + m_nGlpiExDataBytes" fullword ascii
    $s9  = "Assertion Failed: pIterData == m_pGlpiExData + m_nGlpiExDataBytes" fullword ascii
    $s10 = "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\Steam Client Service" fullword wide
    $s11 = "Assertion Failed: m_hServiceControlManager" fullword ascii
    $s12 = "Assertion Failed: maxLen > 0 && maxLen <= INT_MAX" fullword ascii
    $s13 = "Assertion Failed: IsSupported()" fullword ascii
    $s14 = "Assertion Failed: NULL == s_pSingleObjectThis" fullword ascii
    $s15 = "Assertion Failed: 0 == m_nItems" fullword ascii
    $s16 = "Assertion Failed: m_pGroup == nullptr" fullword ascii
    $s17 = "Assertion Failed: maxlen >= 1" fullword ascii
    $s18 = "Assertion Failed: idx < m_nItems" fullword ascii
    $s19 = "Assertion Failed: m_nItems > 0" fullword ascii
    $s20 = " \"%s\" not a valid directory" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}