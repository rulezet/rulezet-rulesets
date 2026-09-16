rule _Virus_Danger_Dump_Generic_Dacic_902B1FCB_A_5EBF6E22_Virus_Dange_518 {
  meta:
    description = "datamaliciousorder - from files Virus.Danger_Dump.Generic.Dacic.902B1FCB.A.5EBF6E22.vir, Virus.Danger_Dump.Generic.Dacic.902B1FCB.A.B00630CE.vir, Virus.Danger_Dump.Generic.Dacic.902B1FCB.A.F8A4DE1F.vir, Virus.Danger_Generic.Dacic.902B1FCB.A.4F297082.vir, Virus.Danger_Generic.Dacic.902B1FCB.A.62A5D887.vir, Virus.Hijack_Gen.Trojan.ShellObject.08Z@a0a9m9p_3_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.08Z@a0a9m9p_4_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.08Z@a0a9m9p_5_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.08Z@a0a9m9p_6_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.uCZ@amHJK4p_7_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.uCZ@amHJK4p_8_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.uCZ@amHJK4p_9_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.uGZ@ayM4QWg_12_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.uGZ@ayM4QWg_13_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.uGZ@ayM4QWg_15_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.uGZ@ayM4QWg_16_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "acd200772db39aa17c40e6abab9840cf4343ad4bcd2b855269683bff8a87c6e8"
    hash2       = "4625c89be43a1bc69b3b11e11b62bb3e61d2b74f53c55fd0cf22875fbb8393d1"
    hash3       = "57e512dfe42f8c1fcb9c5c7d65610e47d2ae5225734fefda3a19811896fbecd6"
    hash4       = "cb7e7bbd8f9a07dc5ea5e7c6605f2a644d7527c1acd55efe413ac3cb641665b8"
    hash5       = "96b7e8002ce52f2815e664953b446a2d85279e01a39950915ce1ed61b26f1abf"
    hash6       = "56b7a4239de7350ee722295e5e018be66015d5d1c69560d82372010ebdf7a795"
    hash7       = "e0db1828383bf124f5864ebd1bb2b92d3d68fa466bee8a7361206ecd873d8c30"
    hash8       = "53bf2671b138447e338407e84f6fb710d9da418e60984fa201924b456c5eb95b"
    hash9       = "609317c1850c79dc0e4a80492125c94653bf5c3380e93269a132c14370c74902"
    hash10      = "60d84455c9ee533b0fe23bb434a5c61c19a0f528cb3dcafdee8c3e0cdd1accc0"
    hash11      = "a05d06dd8c74f8bd2bab0223692dcaca365d4cc4586153dc307009021b858d07"
    hash12      = "a560c16023c3725409ec760c2920968439f8cde18701aae39fb1a9ee303299f5"
    hash13      = "f270f616292bcdef6d16f58b9b6e505d59ab31f6e4be8ec2eaad48eace49fd57"
    hash14      = "89e5008b378f0e1bea0fe4d34a3f9f25f0c5e78ae4f4c145dc339db614717e3e"
    hash15      = "da141d4ab52bc5536156a56e132a32a91696de67f04a8e36d30b6274af38a8ee"
    hash16      = "4eed0e4988464decd54524424e2a7e0d41791bfe0c3886a6d282865b414deaf1"

  strings:
    $s1 = "Gaara The Kazekage By : Paraysutki VM Community" fullword wide
    $s2 = " Kota Cantik - Paray City" fullword wide
    $s3 = "Destroy HokageFile, KSpoold, AutoitV3, Autoruner, BlueFantasi, Sys, VBSvir, PornFile, and Kick Anbu-Team-Sampit" fullword wide
    $s4 = "Mission" fullword wide
    $s5 = "Kazekage Was Here" fullword wide
    $s6 = "Kazekage Games Action" fullword wide
    $s7 = "Kazekage of the Sand" fullword wide
    $s8 = "06.01.2008 (A) Update" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}