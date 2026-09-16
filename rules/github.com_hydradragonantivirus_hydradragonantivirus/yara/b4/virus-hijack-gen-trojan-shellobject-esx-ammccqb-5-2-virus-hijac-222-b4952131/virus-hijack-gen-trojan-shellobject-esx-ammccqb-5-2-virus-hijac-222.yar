import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_eSX_amMcCQb_5_2_Virus_Hijac_222 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_5_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_6_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_7_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_8_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_9_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_10_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_11_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_15.vir, Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23a25cc2feec851e0d1dbcb3edabe0d02373f176b4526cdb3abd97795b5a5c4d"
    hash2       = "3cd8bd3e1455de6c6160e4731f07a7b9ec8791dba764ec7f12a154b6d5e2c086"
    hash3       = "99e622ccef22fa029d43a80190b2bf753deabeaec20392f37b4dcad1be1bf0ce"
    hash4       = "5847c0d50553d832c289b21658cf64bdae66267b2ef73b3751231791c076e525"
    hash5       = "94143e3c5b8bf576088fbdd4f8e39dabb3fa3deb0d3e54c9f019a0c50027f333"
    hash6       = "c7f9226d258791bc3b7c2459e2e1764be913a0985a60ca6bcd67fadbbaf5462c"
    hash7       = "ba64fce50534b1583891982a16956c9a24ae91daea1668605d102620b6677b2d"
    hash8       = "cf617c50ba14391b1d4304d2d89eae47be73b674a501f2f2651cd50e46e58325"
    hash9       = "a51d302b290f4adb2da2151a0e108dc587a629823864d99310dcb2e56fb5feb3"

  strings:
    $s1  = "3,\"System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\",\"C:\\Windows\\assembly\\NativeImages_v4.0.30319" ascii
    $s2  = " PALLADIUM AND BILL GATES - FUCK TCPA, PALLADIUM AND BILL GATES - FUCK TCPA, PALLADIUM AND BILL GATES - FUCK TCPA, PALLADIUM AND" ascii
    $s3  = " BILL GATES - FUCK TCPA, PALLADIUM AND BILL GATES - FUCK TCPA, PALLADIUM AND BILL GATES - FUCK TCPA, PALLADIUM AND BILL GATES - " ascii
    $s4  = "FUCK TCPA, PALLADIUM AND BILL GATES - FUCK TCPA, PALLADIUM AND BILL GATES " fullword ascii
    $s5  = " - Jennifer Lopez - SKELL - gogoprog [He's a nice programmer !] - and the ones I forgot (Sorry :p)" fullword ascii
    $s6  = "    FUCK TCPA, PALLADIUM AND BILL GATES - FUCK TCPA, PALLADIUM AND BILL GATES - FUCK TCPA, PALLADIUM AND BILL GATES - FUCK TCPA," ascii
    $s7  = "    FUCK TCPA, PALLADIUM AND BILL GATES - FUCK TCPA, PALLADIUM AND BILL GATES - FUCK TCPA, PALLADIUM AND BILL GATES - FUCK TCPA," ascii
    $s8  = "        Birichina - BIG_OUF - Steadyson - Dam's - crocodingue - Wabren the gnome - Angelina jolie - TuX - LaTribu - Koto - PassX" ascii
    $s9  = "Have a look at http://antitcpa.alsherok.net/ " fullword ascii
    $s10 = "        Birichina - BIG_OUF - Steadyson - Dam's - crocodingue - Wabren the gnome - Angelina jolie - TuX - LaTribu - Koto - PassX" ascii
    $s11 = " FUCK BUSH " fullword ascii
    $s12 = " PLEASE, USE LINUX TO FUCK MICROSOFT AND THEIR FUCKING TCPA" fullword ascii
    $s13 = "K BUSH FUCK BUSH FUCK BUSH FUCK BUSH FUCK BUSH FUCK BUSH FUCK BUSH FUCK BUSH FUCK BUSH FUCK BUSH FUCK BUSH FUCK BUSH FUCK BUSH F" ascii
    $s14 = "UCK BUSH FUCK BUSH FUCK BUSH FUCK BUSH FUCK BUSH FUCK BUSH FUCK BUSH FUCK BUSH FUCK BUSH FUCK BUSH FUCK BUSH FUCK BUSH FUCK BUSH" ascii
    $s15 = "    THANKS TO MARIE-JEANNE !!!" fullword ascii
    $s16 = "ERROR : You are still using a Microsoft Product !" fullword ascii
    $s17 = "Linux is going to own your system !" fullword ascii
    $s18 = "Linux ownz yah system !" fullword wide
    $s19 = "You can solve this problem by typing 'format c:' in a DOS prompt, then install GNU/Linux (www.debian.org)" fullword ascii
    $s20 = "Error : Your system seems to be unstable because you are still using Microsoft Windows." fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "98dfd9b9e184a03c6ea488ca38f4797e" and (8 of them)
    ) or (all of them)
}