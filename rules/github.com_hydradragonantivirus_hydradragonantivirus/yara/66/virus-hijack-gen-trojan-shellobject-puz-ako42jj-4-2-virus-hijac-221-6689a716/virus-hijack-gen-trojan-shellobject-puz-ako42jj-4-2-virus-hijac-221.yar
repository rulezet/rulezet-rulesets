rule _Virus_Hijack_Gen_Trojan_ShellObject_puZ_aKo42Jj_4_2_Virus_Hijac_221 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.puZ@aKo42Jj_4_2.vir, Virus.Hijack_Trojan.GenericKDZ.105924_239_1.vir, Virus.Hooker_Trojan.GenericKD.72461089_1_1.vir, Virus.Hooker_Trojan.GenericKD.72461089_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "07a4111d358e8cddb418a922731ac19176f72aeb437b9f71de41fa73b61a9d7f"
    hash2       = "866f9094d79a7b3d100dc3e109caae790ebc934f49d8c1f121cc598799096ecb"
    hash3       = "e68a69947d4508c9c50322964c164c6bb9acf9ec50e9515d684fcb9616fae667"
    hash4       = "90aeb643a0072bbb57dd767511158b0b19dd8b58d5e8b35c838512ee9df31fbc"

  strings:
    $s1  = "The Windows SDK Configuration tool presents both a command-line and a GUI interface that allows users to query which versions of" ascii
    $s2  = "The Windows SDK Configuration tool presents both a command-line and a GUI interface that allows users to query which versions of" ascii
    $s3  = "MAn unknown error occurred during execution of Windows SDK Configuration tool." fullword ascii
    $s4  = "jWindows SDK Configuration tool  is unable to determine the processor architecture. Please contact support.A" fullword ascii
    $s5  = "The Windows SDK Configuration tool was unable to set this version of the SDK as the current version. Please verify the selected " ascii
    $s6  = "The Windows SDK Configuration tool was unable to set this version of the SDK as the current version. Please verify the selected " ascii
    $s7  = ".An invalid command line argument is specified." fullword ascii
    $s8  = "$Windows SDK Configuration Tool Error" fullword ascii
    $s9  = "~The Windows SDK Configuration Tool has successfully set Windows SDK version {0} as the current version for Visual Studio 2008." fullword ascii
    $s10 = "GWindows SDK Configuration tool did not find any installed Key products." fullword ascii
    $s11 = " the Windows SDK are installed on a current system and then set which version of the SDK is used by Visual Studio." fullword ascii
    $s12 = "NThe Windows SDK Configuration Tool did not detect any registered Windows SDKs." fullword ascii
    $s13 = "Another instance of the Windows SDK Configuration tool has been detected." fullword ascii
    $s14 = "Windows SDK Configuration Tool" fullword ascii
    $s15 = "Missing Components:" fullword ascii
    $s16 = "&Windows SDK Configuration Tool Warning" fullword ascii
    $s17 = "Using Visual Studio with these components missing may cause headers, libraries and tools used in both managed and native scenari" ascii
    $s18 = "Using Visual Studio with these components missing may cause headers, libraries and tools used in both managed and native scenari" ascii
    $s19 = "Select Visual Studio Versions:" fullword ascii
    $s20 = "3Please check at least one version of Visual Studio." fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}