rule _Virus_Hijack_Gen_Trojan_ShellObject_f8X_aG5Bc5o_4_2_Virus_Hijac_159 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_4_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_5_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_8_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_10_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_11_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_12_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_13_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_14_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_1_2.vir, VirusShareTrojanSiggen817711.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6cd2a3f2ab58ceba304b685d80ec99cee98293281f554f4b247bc9ab5043880d"
    hash2       = "ea98f7689c0417e440e1d27c4cbc44d8e94698ae907024685b374f0a2f431ced"
    hash3       = "3a0f644cb37624ab9f60b7e6706582255a016628c8c78c94d829ecc3ac9429f6"
    hash4       = "a1f73c852f46af89ba4d6ffa45263ad6de9327da6f3ffef7218213441bdfab73"
    hash5       = "50352927df7d25fd238015087b304fbb5a4180ac8743ad9462c9e726535e996a"
    hash6       = "64d7be253b0683466635cb9ccab39bee55c812e9330814b6ce3a44039ddb5ef5"
    hash7       = "bb54c0b4b5f9b5ebe24d3a95ca2c5a237d65193c6f4901d4969ead3b60a684e4"
    hash8       = "c47d2baf377420863029283acb7f69d110fe7c2387caa25e3365126e3e4a7495"
    hash9       = "90fdc7a6f770c7e572f89c673657056b2648afb25355cea6519bf38088d76175"
    hash10      = "bd6de74eabbdb72321816001868b945a08876fea3495d6f5f7af2598923b5ab1"

  strings:
    $x1  = "\"20200709105405.528\",\"1152\",\"448cdc75f99b2efafd89adcda99c9218f1f09adc63557505c57e855ec133c5b0\",\"1880\",\"process\",\"Crea" ascii
    $x2  = "\"20201105030902.519\",\"1564\",\"105046a5449897b6f2c97d60265d6d6cc61c426029b7cac08b4c62a4cf01d25f\",\"2032\",\"process\",\"Crea" ascii
    $s3  = "ternalW\",\"SUCCESS\",\"516\",\"lpApplicationName->(null)\",\"lpCommandLine->C:\\WINDOWS\\system32\\HelpMe.exe\"" fullword ascii
    $s4  = "ternalW\",\"SUCCESS\",\"1408\",\"lpApplicationName->(null)\",\"lpCommandLine->C:\\WINDOWS\\system32\\HelpMe.exe\"" fullword ascii
    $s5  = "\"20200709105410.515\",\"1152\",\"448cdc75f99b2efafd89adcda99c9218f1f09adc63557505c57e855ec133c5b0\",\"1880\",\"registry\",\"Reg" ascii
    $s6  = "\"20200703104936.840\",\"1836\",\"HelpMe.exe\",\"824\",\"registry\",\"RegOpenKeyExW\",\"FAILURE\",\"\",\"hKey->HKEY_CURRENT_USER" ascii
    $s7  = "\"20201105030907.507\",\"1564\",\"105046a5449897b6f2c97d60265d6d6cc61c426029b7cac08b4c62a4cf01d25f\",\"2032\",\"registry\",\"Reg" ascii
    $s8  = "W\",\"SUCCESS\",\"0x000000e0\",\"hKey->HKEY_CURRENT_USER\",\"lpSubKey->Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\U" ascii
    $s9  = "\"20200703104936.940\",\"1836\",\"HelpMe.exe\",\"824\",\"registry\",\"RegQueryValueExW\",\"FAILURE\",\"\",\"hKey->0x00000120\"," ascii
    $s10 = "\"20201014181015.613\",\"1400\",\"HelpMe.exe\",\"1772\",\"registry\",\"RegOpenKeyExW\",\"SUCCESS\",\"0x0000009c\",\"hKey->0x0000" ascii
    $s11 = "\"20200703104936.940\",\"1836\",\"HelpMe.exe\",\"824\",\"registry\",\"RegOpenKeyExW\",\"SUCCESS\",\"0x00000120\",\"hKey->0x00000" ascii
    $s12 = "\"20200703104936.840\",\"1836\",\"HelpMe.exe\",\"824\",\"registry\",\"RegQueryValueExW\",\"FAILURE\",\"\",\"hKey->0x0000011c\"," ascii
    $s13 = "\"20200703104936.820\",\"1836\",\"HelpMe.exe\",\"824\",\"registry\",\"RegQueryValueExW\",\"FAILURE\",\"\",\"hKey->0x0000011c\"," ascii
    $s14 = "\"20201014181015.613\",\"1400\",\"HelpMe.exe\",\"1772\",\"registry\",\"RegQueryValueExW\",\"FAILURE\",\"\",\"hKey->0x0000009c\"," ascii
    $s15 = "\"20200703104936.840\",\"1836\",\"HelpMe.exe\",\"824\",\"registry\",\"RegQueryValueExW\",\"FAILURE\",\"\",\"hKey->0x00000116\"," ascii
    $s16 = "\"20200709105405.578\",\"1152\",\"448cdc75f99b2efafd89adcda99c9218f1f09adc63557505c57e855ec133c5b0\",\"1880\",\"registry\",\"Reg" ascii
    $s17 = "\"20200703104936.840\",\"1836\",\"HelpMe.exe\",\"824\",\"registry\",\"RegQueryValueExW\",\"SUCCESS\",\"\",\"hKey->0x00000116\"," ascii
    $s18 = "\"20200703104936.840\",\"1836\",\"HelpMe.exe\",\"824\",\"registry\",\"RegQueryValueExW\",\"SUCCESS\",\"\",\"hKey->0x0000011c\"," ascii
    $s19 = "\"20200703104936.840\",\"1836\",\"HelpMe.exe\",\"824\",\"registry\",\"RegQueryValueExW\",\"FAILURE\",\"\",\"hKey->0x0000011c\"," ascii
    $s20 = ",\"SUCCESS\",\"0x000000a0\",\"lpFileName->C:\\448cdc75f99b2efafd89adcda99c9218f1f09adc63557505c57e855ec133c5b0\",\"dwDesiredAcce" ascii

  condition:
    (uint16(0) == 0x5a4d and (1 of ($x*) and 4 of them)
    ) or (all of them)
}