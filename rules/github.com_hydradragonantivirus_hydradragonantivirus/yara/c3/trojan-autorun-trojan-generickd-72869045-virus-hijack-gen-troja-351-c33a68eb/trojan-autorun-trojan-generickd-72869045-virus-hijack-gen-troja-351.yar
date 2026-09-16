rule _Trojan_Autorun_Trojan_GenericKD_72869045_Virus_Hijack_Gen_Troja_351 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Trojan.GenericKD.72869045.vir, Virus.Hijack_Gen.Trojan.ShellObject.dyX@ai9jxwp_1_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_104_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_105_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_106_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_85_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_10_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_11_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.fyY@aOF3i8p_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g0W@a4@lcVd_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g0W@a4@lcVd_7_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g0W@a4@lcVd_9_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g0W@aq5b2kh_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_15_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_16_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_17_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_18_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_15_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_2_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_3_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.p8W@aCNb4Uo_5_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.p8W@aCNb4Uo_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b4d08c1939546a758d6fe9b1b5284dc628aff3fef3cb798a4e535143a008a56"
    hash2       = "9a98a2728de2eea7db2532bbf8f79c6ec1dc6a120fe07103807b03434acedd84"
    hash3       = "1402d55ebe79764aa6b500d90065bfe6cac3be6e4b121d503aade48ba3beab58"
    hash4       = "b855bce10c0efd4998e88e95f6bfa4a2f6088c7c5b1befadcff2bb2045f159c7"
    hash5       = "7c9e89c6d6226a5bbb0a4027211b230c847f293a3162d91841125bf0ad032ad9"
    hash6       = "b1b1a9fb160b36ba22f829ffbd02988ba821a5649910c7f2cc9b2264e0dc12f9"
    hash7       = "9dd481aae9a5d9bb4492b165f159bb9b6e7d7a9fc94fa24820790c8c1d87ee10"
    hash8       = "70026ec3929b27d3b7979666f6269ba6d6c5691abe9c4eb63fd04989c348f0c1"
    hash9       = "6a3ecd6dd8f8099413faeda6715cf1be7c4fd9388a5e35e2084d7641fc143965"
    hash10      = "b2108dfb3889c739424c76cfab89967b106303bbb48527797663968a5fad0c9c"
    hash11      = "9b1f053694c3db989f5c342cf8e2239bee4a1942950b85043637104969e007fe"
    hash12      = "91108d07454bd8e212cc115ef1211832c7fcadce9bb9fbae1000811f0ccaad7b"
    hash13      = "322b1709b0a1998c1bcc8d7ecf62946f9bc72e205ae3f51181890f71efcba474"
    hash14      = "d77b112f1683e3c12780036badc6740837837590150bd82023b8f87eb19ac119"
    hash15      = "b191c91e710f1e6d5bba7192208e4582b57d6ca6ab1478dbb8b815207d74aa5f"
    hash16      = "819bdd89651a57972b9b57227d3b6bd3d94ff991732ba0b0e8459b9fb607a9f4"
    hash17      = "6300694b02f0d03c3a18fe78114e8ee3bb4ccb33360a8beef079c18ca3bc5e8a"
    hash18      = "97bc5369195339aa2c26e05972ac2b0e937dbc52dd3a05bc4f29533ffc3d7dbd"
    hash19      = "7a123956fa172c66ed84236a35e0b1f3587bf3d190c604be3c7399fca5ba4571"
    hash20      = "6eca375518c871cbafa55bb8b3f323c5138a90fe23a2590be889548e4186ae0c"
    hash21      = "66d0faa4052007cff3969e3b850cf218a17f7cc2a1282c9c956e0402fcfc35e6"
    hash22      = "1300abe8989a2b3b5e1ab0102c4decd1bb1035a73bacbe2b00a064fb74207f7b"
    hash23      = "88161fa41e18f1d57a2848956c024bd4376d03ece61626be61b46da1c9cd0062"
    hash24      = "4a358cd38d34db61937690de1c080533535f35e44b7ccc50d5b07c5bc183a797"

  strings:
    $s1 = "Assertion Failed: cchEncodedData >= ( cubData * 2 ) + 1" fullword ascii
    $s2 = "Assertion Failed: eKeyType == k_ECryptoKeyTypeRSAPublic" fullword ascii
    $s3 = "%s -e \"load('dotty.lefty');dotty.protogt.lserver='neato';dotty.simple('%Ns');\"" fullword ascii
    $s4 = "Assertion Failed: pchEncodedData" fullword ascii
    $s5 = "Assertion Failed: cchEncodedData > 0" fullword ascii
    $s6 = "Assertion Failed: pData" fullword ascii
    $s7 = "PowerA Xbox One Series X Controller" fullword ascii
    $s8 = "Amazon Luna Gamepad" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}