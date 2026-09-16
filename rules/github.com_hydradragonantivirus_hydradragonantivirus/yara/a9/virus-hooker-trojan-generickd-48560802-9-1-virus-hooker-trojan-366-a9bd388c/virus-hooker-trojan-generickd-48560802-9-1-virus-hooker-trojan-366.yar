import "pe"
rule _Virus_Hooker_Trojan_GenericKD_48560802_9_1_Virus_Hooker_Trojan__366 {
  meta:
    description = "datamaliciousorder - from files Virus.Hooker_Trojan.GenericKD.48560802_9_1.vir, Virus.Hooker_Trojan.GenericKD.48705378_1.vir, Virus.Hooker_Trojan.GenericKD.64030783_1.vir, Virus.Hooker_Trojan.GenericKD.64731121_1.vir, Virus.Hooker_Trojan.GenericKD.67881389_1.vir, Virus.Hooker_Trojan.GenericKD.72461089_1_1.vir, Virus.Hooker_Trojan.GenericKD.72461089_2.vir, Virus.Hooker_Trojan.GenericKD.72483755_1_1.vir, Virus.Hooker_Trojan.GenericKD.72483755_2_1.vir, Virus.Hooker_Trojan.GenericKD.72483755_3_1.vir, Virus.Hooker_Trojan.GenericKD.72483755_4.vir, Virus.Hooker_Trojan.GenericKD.72587580_1_1.vir, Virus.Hooker_Trojan.GenericKD.72587580_2.vir, Virus.Hooker_Trojan.GenericKDZ.94849_1.vir, Virus.Hooker_Trojan.VB.Agent.AWT_1.vir, Virus.Hooker_Win32.Backdoor.Agent.A_1_1.vir, Virus.Hooker_Win32.Backdoor.Agent.A_2.vir, Virus.Hooker_Win32.Ramnit.N_1.vir, Virus.Infector _Win32.Expiro.Gen.7_1.vir, Virus.Infector_Dropped.Trojan.Dropper.Delf.BB_1.vir, Virus.Infector_Dropped.Win32.Elkern.B_1.vir, Virus.Infector_Gen.Heur.Mint.Hiamoe.20_1_1.vir, Virus.Infector_Gen.Heur.Mint.Hiamoe.20_2.vir, Virus.Infector_Gen.Heur.Mint.SP.Sneaky.1_1.vir, Virus.Infector_Gen.Trojan.Heur.ei0frDAUi!mib_1.vir, Virus.Infector_Gen.Trojan.Malware.1q3@aunLb5ni_1.vir, Virus.Infector_Gen.Trojan.Malware.2q3@aunLb5ni_1.vir, Virus.Infector_Gen.Trojan.Malware.5q3@aK8SiHob_1.vir, Virus.Infector_Gen.Trojan.Malware.eS2baCu9Asoi_1.vir, Virus.Infector_Gen.Trojan.Malware.Iq3@aunLb5ni_1_1.vir, Virus.Infector_Gen.Trojan.Malware.Iq3@aunLb5ni_2_1.vir, Virus.Infector_Gen.Trojan.Malware.Iq3@aunLb5ni_3.vir, Virus.Infector_Gen.Trojan.Malware.Kq3@aunLb5ni_1.vir, Virus.Infector_Gen.Trojan.Malware.Lq3@aunLb5ni_1_1.vir, Virus.Infector_Gen.Trojan.Malware.Lq3@aunLb5ni_2_1.vir, Virus.Infector_Gen.Trojan.Malware.Lq3@aunLb5ni_3.vir, Virus.Infector_Gen.Trojan.Malware.lS3@aabLwqji_1.vir, Virus.Infector_Gen.Trojan.Malware.Mq3@aunLb5ni_1_1.vir, Virus.Infector_Gen.Trojan.Malware.Mq3@aunLb5ni_2_1.vir, Virus.Infector_Gen.Trojan.Malware.Mq3@aunLb5ni_3.vir, Virus.Infector_Gen.Trojan.Malware.mS3@aabLwqji_1.vir, Virus.Infector_Gen.Trojan.Malware.nS3@aabLwqji_1.vir, Virus.Infector_Gen.Trojan.Malware.Oq3@aunLb5ni_1.vir, Virus.Infector_Gen.Trojan.Malware.pS3@aabLwqji_1.vir, Virus.Infector_Gen.Trojan.Malware.Qq3@aunLb5ni_1.vir, Virus.Infector_Gen.Trojan.Malware.qS3@aabLwqji_1.vir, VirusShareBATSiggen250_88_1.vir, VirusSharemodificationofWin32Virut56_4_1.vir, VirusSharemodificationofWin32Virut56_8_1.vir, VirusShareTrojanBtcMine155_1.vir, VirusShareTrojanBtcMine1812_1.vir, VirusShareTrojanClick257946_1.vir, VirusShareTrojanClick331128_1_1.vir, VirusShareTrojanClick331128_2_1.vir, VirusShareTrojanClick331128_3_1.vir, VirusShareTrojanClick331128_6_1.vir, VirusShareTrojanClipper50_1.vir, VirusShareTrojanDownLoad234625_2_1.vir, VirusShareTrojanDownLoad38014_1.vir, VirusShareTrojanDownLoader1061384_1.vir, VirusShareTrojanDownLoader1219594_1.vir, VirusShareTrojanDownLoader1350712_1.vir, VirusShareTrojanDownLoader2255152_1.vir, VirusShareTrojanDownLoader2331273_1.vir, VirusShareTrojanDownLoader2352349_1.vir, VirusShareTrojanDownLoader2553612_1.vir, VirusShareTrojanDownLoader2611513_1.vir, VirusShareTrojanDownLoader2632246_1.vir, VirusShareTrojanDownLoader2639910_1.vir, VirusShareTrojanDownLoader3352739_1.vir, VirusShareTrojanDownLoader3951305_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5dfbac5b2c733889241c86e6d799d146274d682c628df3cebcf84caabecf0687"
    hash2       = "acddc5f6ae4b9c1b80b24649b649ec39444e3120c8e6b8d5a20361f06abf3c31"
    hash3       = "0dbd71f42afd6e0517ad66b202875c10c80d0be04bb69db8e8bd19b1c3d58d85"
    hash4       = "bf6b57ff4efd90fcb7a9358ad977082028555ac9f26c37dd44b90f47a2fcc96f"
    hash5       = "93e1751d0b5e188929269abb7417062b16be003b5ff3f1fa52c218da2e96cce4"
    hash6       = "e68a69947d4508c9c50322964c164c6bb9acf9ec50e9515d684fcb9616fae667"
    hash7       = "90aeb643a0072bbb57dd767511158b0b19dd8b58d5e8b35c838512ee9df31fbc"
    hash8       = "fb35f04e4da5e30f2ae8b935b55c87d36d896f155cdc0e7ff3dd6e7a418edd30"
    hash9       = "b4c4605b32dbcbf1bda88bc05b2a71757e06e572ffb1dab58c4c0d28f9715582"
    hash10      = "05765b0b9b00219b39954d21426119288b712119e599ac84d21bf5f604c94b8f"
    hash11      = "3535a218ecd54ea4f16bf768fa4cb310b0e79f758d6b6d2bfb57a6cc91fed0ad"
    hash12      = "42289a87d4e69948b5cacf3d540a84c26904b115cc62770b10ed83c8a8730d23"
    hash13      = "625fa4f0c545b1dd9aaa29f039a1607f5f12dfa0be04154a79bfb09609849e9b"
    hash14      = "fd9302315857738a345216d5bba1002c6eb90a885de2d8db9ef7e8afb437be95"
    hash15      = "6d614471691193440e0326fd127d26c31ddc5b830f82a8df693c3178ec5692a6"
    hash16      = "94ea10cebb9dbbf01aa4576ee118874113d0fa43dda03e44e72da0bf87bf16d1"
    hash17      = "455a48862b356d7440df2aac9f1c874476921389bb29062ffe1d259a029a05c6"
    hash18      = "4b0e91f435ebc6fcf8b35f71c7081e88093bff24ab27c2c4b4dcb920bd6a5a07"
    hash19      = "502710441c7835b16731383c15ea3e9d41f750126c9f31da55c258ed51137657"
    hash20      = "5d7184807ae495bfc8b5267a584db52c8a933033881b3db3de503eeb6fac328e"
    hash21      = "81150558d7ec49f939fe7712adde551e902811835edf16fbdde9a4ad535c81b2"
    hash22      = "0ec2b92a7838dd7325db08b7a93f3deef19a5e11972ed64e753793f5f7ca6561"
    hash23      = "966f43636e45e27868a30ae7d5e122e22ee997a61caacb56ac898ac7dfa66462"
    hash24      = "53a13b6c5a8b78a80cabaf479dbbc9a347515792f31d33e89f446c27f399de1d"
    hash25      = "c52fa281ae4471782914d02f1c476f9ba269ecae9390e4a883e97c501f86cbbd"
    hash26      = "85fc817c1c8dda19e804a3aaa4081ca4f0824b066ad3e0bbc5a67e4645b7fe98"
    hash27      = "d29e36469f79344586b96791c39a0f6f24abf5a52e7a75ef07f93b6dd815f7d4"
    hash28      = "b395131f3f2d4baf460e945aeba7b78131765d4d6a183b1b3295f86524378279"
    hash29      = "6d0dcb774173b3df22ef203279fd51387e470663280c29360ab310edadaaab9e"
    hash30      = "2cadcd8b1f8ecdb43bff150c0be42223c5bb3237fe1effbf0527ee84da508720"
    hash31      = "b8bfe89534c58af0a5e0ac2b447802cce436721fdf5a64cdabf4d2824e7f7141"
    hash32      = "1c4fe9e884172030bda8880c03a460a0a3f1761337195cf9fc275bdd01ca6d5c"
    hash33      = "2c36705fcbdb0356ccf8f7d3f4f68013bc5298ad19440b64d2bb966e8eac8c36"
    hash34      = "4e0ac4f196ab6911f61a4bb9ee6b963be52bb561d87724af4cc1480ac427245f"
    hash35      = "a316d2edeae0147ec627ae5d020170e6666f5b8f454f703c611cf00983ae1deb"
    hash36      = "09850c1c0722d9137b54bb9b807502cf33e9aa558b688e83321b4bae16cb03a2"
    hash37      = "ef2cb684ff9c041709275328e01baa023523b4b90226cecdeec88e454a735084"
    hash38      = "ec0ba176127f3722463316968697fc35aa48225b87cb820fd4872f1aa8a731e8"
    hash39      = "01d7e3fb56bf98d4545e055647206981243c1165914975696031bc92b00fc644"
    hash40      = "b7031bd32f110b3183848fc7a05313bbfd2581936c862e20d7c5b63fb8e60cde"
    hash41      = "c9e44ce8ebac7184774e4ae408d5f98dbc4c468a085e9d0ec517249d754329ec"
    hash42      = "287bf639058da2d199fbf5cccc4f948b9c7cb1fad6118cce81175798ab228e52"
    hash43      = "72e9e01c0a58a4aa1ea716c3b9056adc3996994c3da85ae68f4ccae4174c82ba"
    hash44      = "4e19ebc755e0145db982d0a6a7af8951779a57db0f4c7fd1bb43e83c53e2bff4"
    hash45      = "ca8cd2d3d060e43969090a2a3f509704e8b59fac05a529736ceb36d2dc214c5d"
    hash46      = "b65de413e2e77574ab6addee12eed300bc54865fdfa6728e5ab27a0971de07d8"
    hash47      = "1ad0db2cc5121ee494ef38b555b9e28f9837f0056d4bcaeeffc06bb5d8efc01c"
    hash48      = "dcd17ba2d4cf7c5a73ee78948872aa032fde562f415ed28aa5cc85138c458d16"
    hash49      = "9239aeaf44f08a5d002efdabc9b6f4c01abccde5f3292c5a0f6bc95e08daf182"
    hash50      = "7373a781949429dd8274b829574d19ef6883dfe50fefa66898b6a35308c579ee"
    hash51      = "18f532cae73cee8472351ee5f82a39348b5040de756e9d0500b185f181a939d8"
    hash52      = "2232141d329267f88679decd77f3992b67862e751aa2deaa6585cf8116eddeda"
    hash53      = "5865d276edcd50fd6f4b8e6b1734a9978b49ad4ebbd3c1b73f9723c140e80cf4"
    hash54      = "a1b31b78023158adf0360947d5d12512ac0132b3b758720480e06341fe058946"
    hash55      = "7114291f854e30f688cce8a770ab301457098c007c586981d8f793d76a7f7eba"
    hash56      = "3be651fb702da455b0c028601d23bd70d8b8f87d33487fff08e7c1167811a181"
    hash57      = "a6a5b73980813863e3246ef9eaff582e8d1a9ac0bd2726cb7494e7b942110c5e"
    hash58      = "497b89ad9ae507b9f6450ca584c45fe954b0d5b07a846ab4a0e11f6478df7e4b"
    hash59      = "71c0553089230134457ad91dce1e93c7d4873436115f2c30170c95f94a576b54"
    hash60      = "d7c431af425a4a49999c586ba41e3b210b43e9a8ec65d1710459f8ffa9ae584b"
    hash61      = "45a66a58046646b91234288d52958a064e416be85ba5ac11639c0c5ea991bdf1"
    hash62      = "e136e4a2459e1a16d5a96a8c1370c9bb3a40686da2e69cdb6bd3870fed79fc35"
    hash63      = "38f8d343ce34042540ebb4803a134082aae6c4265188f2d077d046fec8174f1f"
    hash64      = "1d7e05c15d76235be5127db9166b3c299ddc7dad7794bdcac8544650c6103fa5"
    hash65      = "4141d6878e71d270ec4edc337f3f5c7d613ebb8e5d6aadb484443d3d59242187"
    hash66      = "7ae2b18015c6a31c750c64dc1b59c56e97d8742e91afcdf63b6e597c30d74f5f"
    hash67      = "9b780849eaeec69fdff82c92545f33b1a6aa6c582b3ccdabcaefae95eed95197"
    hash68      = "5bc68cbe4211617bb6000f9c1a1ef6df0641c5c6c802a17bfb5685b3c6ca7e51"
    hash69      = "97f1ea6c1ac3cff9f761bf0650eedc8cd23b8bb61c5486b1b91a18a1c6e664c9"
    hash70      = "1297c5627e07c6be7fb4c316c13919050605cf6e95902657de519c35f9bf6285"
    hash71      = "607d6fb5767e4e524e4a12ed9513f93be6e9fb83ab34c7d1573cf106b0a9153d"

  strings:
    $s1  = "legend of mir2\\Change password" fullword ascii
    $s2  = "legend of mir2\\Change password\\" fullword ascii
    $s3  = "start mail input" fullword ascii
    $s4  = "From:Mir2 <" fullword ascii
    $s5  = "Independent Bitmapj(" fullword ascii
    $s6  = "legend of mir2\\Enter" fullword ascii
    $s7  = "legend of mir2\\Enter\\" fullword ascii
    $s8  = "legend of mir2\\Registry" fullword ascii
    $s9  = "legend of mir2\\Registry\\" fullword ascii
    $s10 = "Canvas does not allow drawing Clipboard does not support Icons" fullword wide
    $s11 = "[Setup" fullword ascii
    $s12 = "[Server" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "aae410db5a351d384de2e35faf59497e" and (8 of them)
    ) or (all of them)
}