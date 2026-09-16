rule _Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_34_1_Virus_Hijac_473 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_34_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_61_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_81_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_90_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_92_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f4W@aixDqOn_10_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@a45ajXp_4_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@a45ajXp_8_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@a8oG5if_15_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@a8oG5if_7_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aCXl7mh_5_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aGAMRTl_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aGAMRTl_26.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ce6b88f3b55f2c20fd56f084b8f9b8b5beed7a43a857cdccb442c2396fd54b3"
    hash2       = "b168e3d040f893b27f3da3a99987421bbe5aa2f2b1bc724ca960a62ffd517a37"
    hash3       = "6327f28e47642243cd0ef9330c0341fd38640ed8b37d935547fa676528a92f8e"
    hash4       = "71329c7d9a7e8dc1335a1284f197b114068fc19e0c88db1df9792ca808d3decf"
    hash5       = "ca3bc292017d7d1c8e8359a3c5aefce6ecf8c61bcb005a803bd51d91ab995d2e"
    hash6       = "69bd9416563472f6c30ecf98e0f5e54b0b4381fe116f5a0f115411d6add8a794"
    hash7       = "dae446e3d965e70e63a209b6543f22809559b24797e2b115fec4d7bac9187a24"
    hash8       = "b575fd5b9fa3eb4cdf5787bec9d27cdf79214c6f8e8dec0964f1a83d66d5a071"
    hash9       = "086b26ea8266a4b66bfd9132bba2e90e0361a230da7d600302a495fe289affae"
    hash10      = "bdf2e3a65fa08b8b4db08ff20d3c7a463e183e6a85a9676b188b1f8213c3e48a"
    hash11      = "a81480ffec3626872fd4081b03a68e966c7479b3880f450f6f64d6fb67f79619"
    hash12      = "6d1d2b47402b4aaaefb09b514e2b98525b487674a33a064163d70d2fc241e14b"
    hash13      = "162420216366cd47ba9babc17bf2adce60629d8d7fdc66278e0b9943866de1a5"

  strings:
    $s1  = "07-13-2009 22:14 : DTC Install error = 0, SysPrepDtcGeneralize : Enter, d:\\w7rtm\\com\\complus\\dtc\\dtc\\adme\\deployment.cpp " ascii
    $s2  = "11-20-2010 19:58 : DTC Install error = 0, SysPrepDtcGeneralize : Enter, d:\\w7rtm\\com\\complus\\dtc\\dtc\\adme\\deployment.cpp " ascii
    $s3  = "07-13-2009 22:13 : DTC Install error = 0, SysPrepDtcCleanup : Enter, d:\\w7rtm\\com\\complus\\dtc\\dtc\\adme\\deployment.cpp (17" ascii
    $s4  = "07-13-2009 22:13 : DTC Install error = 0, SysPrepDtcCleanup : Exit, d:\\w7rtm\\com\\complus\\dtc\\dtc\\adme\\deployment.cpp (181" ascii
    $s5  = "11-20-2010 18:43 : DTC Install error = 0, SysPrepDtcSpecialize : Enter, d:\\w7rtm\\com\\complus\\dtc\\dtc\\adme\\deployment.cpp " ascii
    $s6  = "11-20-2010 19:58 : DTC Install error = 0, SysPrepDtcGeneralize : Exit, d:\\w7rtm\\com\\complus\\dtc\\dtc\\adme\\deployment.cpp (" ascii
    $s7  = "11-20-2010 19:57 : DTC Install error = 0, SysPrepDtcCleanup : Exit, d:\\w7rtm\\com\\complus\\dtc\\dtc\\adme\\deployment.cpp (181" ascii
    $s8  = "11-20-2010 18:43 : DTC Install error = 0, SysPrepDtcSpecialize : Exit, d:\\w7rtm\\com\\complus\\dtc\\dtc\\adme\\deployment.cpp (" ascii
    $s9  = "07-13-2009 22:14 : DTC Install error = 0, SysPrepDtcGeneralize : Exit, d:\\w7rtm\\com\\complus\\dtc\\dtc\\adme\\deployment.cpp (" ascii
    $s10 = "11-20-2010 19:57 : DTC Install error = 0, SysPrepDtcCleanup : Enter, d:\\w7rtm\\com\\complus\\dtc\\dtc\\adme\\deployment.cpp (17" ascii
    $s11 = "***07-13-2009 21:46 : DTC Install error = 0, Entering DeployDtc, d:\\w7rtm\\com\\complus\\dtc\\dtc\\adme\\deployment.cpp (55) " fullword ascii
    $s12 = "11-20-2010 18:43 : DTC Install error = 0, InstallContacts, Enter, d:\\w7rtm\\com\\complus\\dtc\\dtc\\adme\\deployment.cpp (297) " ascii
    $s13 = "07-13-2009 21:46 : DTC Install error = 0, InstallContacts, Exit, d:\\w7rtm\\com\\complus\\dtc\\dtc\\adme\\deployment.cpp (376) " fullword ascii
    $s14 = "11-20-2010 18:43 : DTC Install error = 0, InstallContacts, Exit, d:\\w7rtm\\com\\complus\\dtc\\dtc\\adme\\deployment.cpp (376) " fullword ascii
    $s15 = "07-13-2009 21:46 : DTC Install error = 0, DeployDtc: SetSddlOnResources finished, d:\\w7rtm\\com\\complus\\dtc\\dtc\\adme\\deplo" ascii
    $s16 = "07-13-2009 21:46 : DTC Install error = 0, InstallContacts, Enter, d:\\w7rtm\\com\\complus\\dtc\\dtc\\adme\\deployment.cpp (297) " ascii
    $s17 = "07-13-2009 21:46 : DTC Install error = 0, Exiting DeployDtc, d:\\w7rtm\\com\\complus\\dtc\\dtc\\adme\\deployment.cpp (139) " fullword ascii
    $s18 = "07-13-2009 21:46 : DTC Install error = 0, DeployDtc: SetSddlOnResources finished, d:\\w7rtm\\com\\complus\\dtc\\dtc\\adme\\deplo" ascii
    $s19 = "07-13-2009 21:46 : DTC Install error = 0, DeployDtc: Calling SetSddlOnResources, d:\\w7rtm\\com\\complus\\dtc\\dtc\\adme\\deploy" ascii
    $s20 = "07-13-2009 21:46 : DTC Install error = 0, DeployDtc: Calling SetSddlOnResources, d:\\w7rtm\\com\\complus\\dtc\\dtc\\adme\\deploy" ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}