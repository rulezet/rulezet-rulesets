import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_19_1_Virus_Hijac_497 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_19_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_30_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_75_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_97_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@a0q1@io_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a8da8312c635607907b65885911dabbe8ad25d74208f0a022cf51f4e80dc0b7a"
    hash2       = "69e0e3f6b4fc2a0317f129a267ddc83af6e67344211a7c6fc288a2a483d50b9f"
    hash3       = "66c51a47aada5d1164dc1039e0d03e5f493ab7fbb53cf9ddcc861124109b6d7d"
    hash4       = "4a23cb28fe1cd87e228be49b8e73fa6eda1475f427575b3f804b7f169f6731c4"
    hash5       = "63ba3767ff03f970b667891a101091818f7b4f6ea792bae3b40116e1f204c180"

  strings:
    $s1  = "[ 3/15 04:30:31] 596.600>  - LsapSetRandomDomainSid: Got lsasrv.dll module? 1" fullword wide
    $s2  = "[ 3/15 04:30:31] 596.600>  - LsapSetRandomDomainSid: LsapGetMessageStrings returned 0x0" fullword wide
    $s3  = "03-15-2021 04:30 : DTC Install error = 0, SysPrepDtcSpecialize : Exit, com\\complus\\dtc\\dtc\\adme\\deployment.cpp (2132) " fullword ascii
    $s4  = "03-15-2021 04:30 : DTC Install error = 0, InstallContacts, Enter, com\\complus\\dtc\\dtc\\adme\\deployment.cpp (310) " fullword ascii
    $s5  = "03-15-2021 04:30 : DTC Install error = 0, InstallContacts, Exit, com\\complus\\dtc\\dtc\\adme\\deployment.cpp (389) " fullword ascii
    $s6  = "[ 3/15 04:30:31] 596.600>  - LsapSetRandomDomainSid: LsarSetInformationPolicy returned 0x0" fullword wide
    $s7  = "ralize : Exit, com\\complus\\dtc\\dtc\\adme\\deployment.cpp (2071) " fullword ascii
    $s8  = "[ 3/15 04:30:31] 596.600>  - LsapGenerateRandomDomainSid: RtlAllocateAndInitializeSid returned 0x0" fullword wide
    $s9  = "[ 3/15 04:30:31] 596.600>  - LsapSetRandomDomainSid: LsapGenerateRandomDomainSid          returned: 0x0. DomainSid is below." fullword wide
    $s10 = "onstall error = 0, Enter MsDtcAdvancedInstaller::Configure, base\\wcp\\plugins\\msdtc\\msdtcadvancedinstaller" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "895fbb56c02c3d2bca3125cef5da8730" and (all of them)
    ) or (all of them)
}