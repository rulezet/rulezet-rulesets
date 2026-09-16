import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_f8X_aian2n_10_2_Virus_Hijac_341 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_10_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_11_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_12_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_13_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_14_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1f73c852f46af89ba4d6ffa45263ad6de9327da6f3ffef7218213441bdfab73"
    hash2       = "50352927df7d25fd238015087b304fbb5a4180ac8743ad9462c9e726535e996a"
    hash3       = "64d7be253b0683466635cb9ccab39bee55c812e9330814b6ce3a44039ddb5ef5"
    hash4       = "bb54c0b4b5f9b5ebe24d3a95ca2c5a237d65193c6f4901d4969ead3b60a684e4"
    hash5       = "c47d2baf377420863029283acb7f69d110fe7c2387caa25e3365126e3e4a7495"
    hash6       = "90fdc7a6f770c7e572f89c673657056b2648afb25355cea6519bf38088d76175"

  strings:
    $s1 = "Outlook Express\\msimn.exe" fullword ascii
    $s2 = "Height$7C" fullword ascii
    $s3 = "Your disk is removed!" fullword ascii
    $s4 = "Hint@UD" fullword ascii
    $s5 = "Default$7C" fullword ascii
    $s6 = "Stone,I hate you!" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "17ed737e8e77e97fd1eb6ad9ba5d3eae" and (all of them)
    ) or (all of them)
}