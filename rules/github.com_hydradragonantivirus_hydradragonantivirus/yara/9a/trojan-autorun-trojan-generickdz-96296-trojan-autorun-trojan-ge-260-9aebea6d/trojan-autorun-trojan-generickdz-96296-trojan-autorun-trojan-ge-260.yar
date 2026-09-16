import "pe"
rule _Trojan_Autorun_Trojan_GenericKDZ_96296_Trojan_Autorun_Trojan_Ge_260 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Trojan.GenericKDZ.96296.vir, Trojan.Autorun_Trojan.GenericKDZ.96296_1.vir, Trojan.Autorun_Trojan.GenericKDZ.96296_2.vir, Trojan.Autorun_Trojan.GenericKDZ.96296_3.vir, Trojan.Autorun_Trojan.GenericKDZ.96296_4.vir, Trojan.Autorun_Trojan.GenericKDZ.96296_5.vir, Trojan.Autorun_Trojan.GenericKDZ.96296_6.vir, Trojan.Autorun_Trojan.GenericKDZ.96296_7.vir, Virus.Hijack_Gen.Trojan.ShellObject.D8W@aCma7ml_1_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.D8W@aCma7ml_2_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.D8W@aCma7ml_3_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.D8W@aCma7ml_4_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.D8W@aCma7ml_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "096a676e460c5bab605b118ee8904d9c63a7af1c5059bf3fdac0a41f8e6f9073"
    hash2       = "0fc622b1587c8c069cadb889350d068dbe585719aea5166f84ed75a1e78ee326"
    hash3       = "cd6f6001efc7c3c446e2017e0c43718db7bc612426601b0f86e1a41e362ae2f2"
    hash4       = "25acd08aab5be0931641cee6d70e5189820476dac4e447a6d9dc05541764dfb1"
    hash5       = "a12312951af87e0536c39ca158710c36ef507b6486350f46b0c1f34183175d9f"
    hash6       = "59e85a7324f1951b70cb8dc45d85dbcc25c12defbe767f9a14483f58106eb417"
    hash7       = "514efbc52b35b98e6a95fe3db716dccf099b41d401759a9f94e7cdaf9f83336d"
    hash8       = "4189a4bfc63e0bded371a6db28b43a8361bda682646a878dcd03ddd8529ec811"
    hash9       = "d2dbaca8e85b641ea02b54350d68532aae4e879896cc6052740dbbef8b5b44d9"
    hash10      = "37080a11cc691459fed0fed208ea628a81e0370adf67f0543987f4c7d5fd0945"
    hash11      = "306ac1603db4155a35a43bc9f6da923619f9c7ad431ac5b58a27ef2c6de2e2a2"
    hash12      = "4a5c05693923dc088424d26b9fdcd19a77724a2b24c2181a3a31d5cb0cef9721"
    hash13      = "21da505e1e7612ecb4a42e7f5258ba89c691860908a822733c4325bdd5548227"

  strings:
    $s1  = "Read Me!.SCR" fullword ascii
    $s2  = "Read Me.SCR" fullword ascii
    $s3  = "Read Me!!!.RAR" fullword ascii
    $s4  = "Command Server. Compiled : 2004/02/15" fullword ascii
    $s5  = "MEMORY DUMPER" fullword ascii
    $s6  = "NUMEGA SOFTICE LOADER" fullword ascii
    $s7  = "Import Load failure" fullword ascii
    $s8  = "Transfer Server. Compiled : 2004/02/15" fullword ascii
    $s9  = "FILE MONITOR" fullword ascii
    $s10 = "Refund`" fullword ascii
    $s11 = "-=CHINA CRACKING GROUP=-" fullword ascii
    $s12 = "ProductID : " fullword ascii
    $s13 = "Server Path : " fullword ascii
    $s14 = "By Trial ACProtect" fullword ascii
    $s15 = "WINDOW DETECTIVE" fullword ascii
    $s16 = "MEMORY EDITOR" fullword ascii
    $s17 = "ADVANCED REGISTRY TRACER" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "d8b32e731e5438c6329455786e51ab4b" and (8 of them)
    ) or (all of them)
}