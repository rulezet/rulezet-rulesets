rule _Virus_Hijack_Gen_Trojan_ShellObject_f8X_aG5Bc5o_4_2_Virus_Hijac_147 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_4_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_5_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_8_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_10_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_11_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_12_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_14_2.vir, VirusShareTrojanSiggen817711.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6cd2a3f2ab58ceba304b685d80ec99cee98293281f554f4b247bc9ab5043880d"
    hash2       = "ea98f7689c0417e440e1d27c4cbc44d8e94698ae907024685b374f0a2f431ced"
    hash3       = "3a0f644cb37624ab9f60b7e6706582255a016628c8c78c94d829ecc3ac9429f6"
    hash4       = "a1f73c852f46af89ba4d6ffa45263ad6de9327da6f3ffef7218213441bdfab73"
    hash5       = "50352927df7d25fd238015087b304fbb5a4180ac8743ad9462c9e726535e996a"
    hash6       = "64d7be253b0683466635cb9ccab39bee55c812e9330814b6ce3a44039ddb5ef5"
    hash7       = "c47d2baf377420863029283acb7f69d110fe7c2387caa25e3365126e3e4a7495"
    hash8       = "bd6de74eabbdb72321816001868b945a08876fea3495d6f5f7af2598923b5ab1"

  strings:
    $s1  = "\"20201105030907.517\",\"1564\",\"105046a5449897b6f2c97d60265d6d6cc61c426029b7cac08b4c62a4cf01d25f\",\"2032\",\"registry\",\"Reg" ascii
    $s2  = "\",\"SUCCESS\",\"\",\"hKey->0x000001e8\",\"lpValueName->Common Desktop\",\"dwType->1\",\"lpData->C:\\Documents and Settings\\All" ascii
    $s3  = "\",\"SUCCESS\",\"\",\"hKey->0x00000144\",\"lpValueName->Common Documents\",\"dwType->1\",\"lpData->C:\\Documents and Settings\\A" ascii
    $s4  = "\"20201105030907.667\",\"1564\",\"105046a5449897b6f2c97d60265d6d6cc61c426029b7cac08b4c62a4cf01d25f\",\"2032\",\"registry\",\"Reg" ascii
    $s5  = "\"20201105030907.657\",\"1564\",\"105046a5449897b6f2c97d60265d6d6cc61c426029b7cac08b4c62a4cf01d25f\",\"2032\",\"registry\",\"Reg" ascii
    $s6  = "\"20201105030907.657\",\"1564\",\"105046a5449897b6f2c97d60265d6d6cc61c426029b7cac08b4c62a4cf01d25f\",\"2032\",\"registry\",\"Reg" ascii
    $s7  = "\"20201105030907.667\",\"1564\",\"105046a5449897b6f2c97d60265d6d6cc61c426029b7cac08b4c62a4cf01d25f\",\"2032\",\"registry\",\"Reg" ascii
    $s8  = "\"20201105030907.627\",\"1564\",\"105046a5449897b6f2c97d60265d6d6cc61c426029b7cac08b4c62a4cf01d25f\",\"2032\",\"registry\",\"Reg" ascii
    $s9  = "\"20201105030907.667\",\"1564\",\"105046a5449897b6f2c97d60265d6d6cc61c426029b7cac08b4c62a4cf01d25f\",\"2032\",\"registry\",\"Reg" ascii
    $s10 = ",\"FAILURE\",\"\",\"hKey->HKEY_LOCAL_MACHINE\",\"lpSubKey->Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution" ascii
    $s11 = "W\",\"SUCCESS\",\"0x00000138\",\"hKey->HKEY_CURRENT_USER\",\"lpSubKey->Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\U" ascii
    $s12 = "W\",\"SUCCESS\",\"0x000001e4\",\"hKey->HKEY_CURRENT_USER\",\"lpSubKey->Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\U" ascii
    $s13 = "W\",\"SUCCESS\",\"0x00000144\",\"hKey->HKEY_LOCAL_MACHINE\",\"lpSubKey->Software\\Microsoft\\Windows\\CurrentVersion\\Explorer" ascii
    $s14 = "W\",\"SUCCESS\",\"0x000001e8\",\"hKey->HKEY_LOCAL_MACHINE\",\"lpSubKey->Software\\Microsoft\\Windows\\CurrentVersion\\Explorer" ascii
    $s15 = "\"20201105030907.517\",\"1564\",\"105046a5449897b6f2c97d60265d6d6cc61c426029b7cac08b4c62a4cf01d25f\",\"2032\",\"synchronization" ascii
    $s16 = "\"20201105030907.517\",\"1564\",\"105046a5449897b6f2c97d60265d6d6cc61c426029b7cac08b4c62a4cf01d25f\",\"2032\",\"synchronization" ascii
    $s17 = "\"20201105030907.517\",\"1564\",\"105046a5449897b6f2c97d60265d6d6cc61c426029b7cac08b4c62a4cf01d25f\",\"2032\",\"synchronization" ascii
    $s18 = "\"20201105030907.547\",\"1564\",\"105046a5449897b6f2c97d60265d6d6cc61c426029b7cac08b4c62a4cf01d25f\",\"2032\",\"registry\",\"Reg" ascii
    $s19 = "xW\",\"SUCCESS\",\"\",\"hKey->0x00000144\",\"lpValueName->Common Documents\"" fullword ascii
    $s20 = "\"20201105030907.547\",\"1564\",\"105046a5449897b6f2c97d60265d6d6cc61c426029b7cac08b4c62a4cf01d25f\",\"2032\",\"registry\",\"Reg" ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}