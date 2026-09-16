import "pe"
rule _Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_56_1_Troj_435 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_56_1.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_615_1.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_726_1.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_779_1.vir, Trojan.Autorun_Dump.Trojan.GenericKDZ.95048_21_1.vir, Virus.Hijack_Backdoor.Hangup.B_158.vir, Virus.Hijack_Backdoor.Hangup.B_176.vir, Virus.Hijack_Backdoor.Hangup.B_195.vir, Virus.Hijack_Backdoor.Hangup.B_209.vir, Virus.Hijack_Backdoor.Hangup.B_278.vir, Virus.Hijack_Backdoor.Hangup.B_33.vir, Virus.Hijack_Backdoor.Hangup.B_47.vir, Virus.Hijack_Backdoor.Hangup.B_50.vir, Virus.Hijack_Backdoor.Hangup.B_91.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_141.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_188.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_196.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_258.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_259.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_294.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_324.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_337.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_340.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_394.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_465.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_88.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d44b62e9a089187e2b6a337c478d0ed81b397dee826189f0b6e602b5ceab4856"
    hash2       = "31b4676721052dc63fbc5da4edccfb82eaf3b5a376612bcd22949a6679431294"
    hash3       = "2e87e0707fb98572322e966c794d4ee8ad33e147e72eea5b7ab21d34ff8c8d21"
    hash4       = "4094aa88f99a9cdd7230a155e0de0eb0e5fe46633f15dd81717949d3731bf7ca"
    hash5       = "e0652ef8ca39395ad1765be52c6691bbe418480b064f9d0b1279f4353f284dc8"
    hash6       = "c5888a8ab45cd4306aabfa1cad80a80aecced75171466f2d42dbc012c26276b5"
    hash7       = "ac6851119355f94b8c55c535833cf8b503ed3b76d5d49c8d9f2b1a7865415ceb"
    hash8       = "3e9bad9304fc7ed39d5d602c0052c590ba7f48bd516c55746682ff1401c34d4f"
    hash9       = "f4b508bfcbeceaa6cec518c8d1afbed61e2dc982ead20ab5ad43ff2d837a06ac"
    hash10      = "2c96c99043d28240fcfb5b12d2e51ab340372877ee77c977e0150f23ad7c5b4a"
    hash11      = "d373d9dbd3a28e72a6373becddef5ba37fb1bd4408910f0680d256509f9f0854"
    hash12      = "ffbc63591ff2527c741d73f7f2d8d72bfb59d5aad0b8e48821200269282e6e3a"
    hash13      = "b579b5c1f1229020bb4f7f4409267453cffdadeb23a7b4317f56eff4b99ed798"
    hash14      = "fa6037c6fe97b079a664a965f474391595121411b2715dd015f256ed75e025ca"
    hash15      = "cde03f053b802edaeffcbf3f64d3f4bc020eed502332ac5c6e04c79f9f803db3"
    hash16      = "04de0df0a7d0d921a387f5afda95ffa9b8bfb578f501076ece95ebb2edc4d4ba"
    hash17      = "6869809131cab3887bd12227a2cc4915f16ef0c4613ce33323e4d5e4946f87b6"
    hash18      = "579c2deb42f27d92c08f82d774801e7d7cd6fe8bf0fd3b88103d5f83b6dc20c3"
    hash19      = "502e1c51a5338cc36c16b2b92f1deb25c6091933dcc38aa048ae55fac6fd05db"
    hash20      = "793dd43ed580a4cc9527dc561d892c0e9f8c5a65c8f54c4b4bcfcf70d2e0effb"
    hash21      = "4ed14b8ca5e6e7b2ac90f53192f02899bfb4038511b4e1f4dac3c276f652d9ac"
    hash22      = "78a5ca3c73fc2d0992b4be70b3c2b4c6c45284137e6349bd987a97cf0db3a038"
    hash23      = "087c5f9c6134096b135448a65ae70591200136d4a795dd8db6e0052f128d3bdc"
    hash24      = "0cd1efd6f5fe468baa8b9b5c04bc6ddd11ea99c0a9fda2d9f2af110134785a96"
    hash25      = "19f07b7ee7b629611df23e89fd3f79914798cb4b9f15b88869d4c3624f722790"
    hash26      = "5f4ecebe7ed3d5551db28ee12c462f1d186275d3be407967f0612413206385a9"

  strings:
    $s1  = "Purchase Line: is defined as the total number of purchase line items processed by the application during aNon Employee User - Ex" ascii
    $s2  = "Purchase Line: is defined as the total number of purchase line items processed by the application during aNon Employee User - Ex" ascii
    $s3  = "Can I transfer the software to another computer or userServer (Standard Edition and/or Enterprise Edition) and the licensed prog" ascii
    $s4  = "Can I transfer the software to another computer or user1 Year Oracle Hosted Term: A program license specifying a 1 Year Oracle H" ascii
    $s5  = "Can I transfer the software to another computer or userServer (Standard Edition and/or Enterprise Edition) and the licensed prog" ascii
    $s6  = "Can I transfer the software to another computer or user1 Year Oracle Hosted Term: A program license specifying a 1 Year Oracle H" ascii
    $s7  = "with your Microsoft account. For more information about the Office Roaming" fullword ascii
    $s8  = "ram are running are counted for the purpose of" fullword ascii
    $s9  = "own most important confidential information or a reasonable degree of care, whichever is greater; (b) to C. Rights Granted" fullword ascii
    $s10 = "osted Term shall commence on the effective" fullword ascii
    $s11 = "BY ACCEPTING THIS A GREEMENT OR USING THE SOFTWA RE, YOU A GREE TO ALL OF THESEr failure" fullword ascii
    $s12 = "ternal: is defined as an individual, who is not your employee, contractor or outsourcer, authorized" fullword ascii
    $s13 = "s actively using the programs at any given time. If you license the Self Service Work Request" fullword ascii
    $s14 = "and the failure does not amount to a major failure. Line licenses from Oracle." fullword ascii
    $s15 = " For more information about the Office Roaming" fullword ascii
    $s16 = "reduced by applying the discount specified above. Notwithstanding anything to the contrary in the previous three sentences,ual i" ascii
    $s17 = "Can I transfer the software to another computer or userconditions. Microsoft warrants that properly licensed software will perfo" ascii
    $s18 = "Can I transfer the software to another computer or user" fullword ascii
    $s19 = "d into the responsibility of another" fullword ascii
    $s20 = "gardless of whether the individual" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "cd53137d547a9a70fc3d0bec0bcae5e8" and (8 of them)
    ) or (all of them)
}