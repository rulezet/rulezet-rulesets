rule _Virus_Sysbot_GenPack_Trojan_GenericKDZ_94923_4_1_Virus_Sysbot_G_388 {
  meta:
    description = "datamaliciousorder - from files Virus.Sysbot_GenPack.Trojan.GenericKDZ.94923_4_1.vir, Virus.Sysbot_GenPack.Trojan.GenericKDZ.94923_5_1.vir, Virus.Sysbot_Trojan.Agent.CYQD_1.vir, Virus.Sysbot_Trojan.Agent.DDOH_1.vir, Virus.Sysbot_Trojan.Agent.EFYN_1.vir, Virus.Sysbot_Trojan.AgentWDCR.JMO_1_1.vir, Virus.Sysbot_Trojan.AgentWDCR.JMO_2_1.vir, Virus.Sysbot_Trojan.AgentWDCR.JMO_3_1.vir, Virus.Sysbot_Trojan.AgentWDCR.JMO_4_1.vir, Virus.Sysbot_Trojan.AgentWDCR.JMO_5_1.vir, Virus.Sysbot_Trojan.AgentWDCR.JMO_6.vir, Virus.Sysbot_Trojan.GenericKD.45640429_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17eaeaedd69db1bc04550d774fc7ba7033bec82f6604b9e42bc065387e72cae2"
    hash2       = "2aeba12a0b1f1eac616a2c42bb6085c36033f51d09d7eeaaafe962c7fd7d15ff"
    hash3       = "470b33370e27e0cc24b339ae0782aa6388489981e3b1b2a7a9ecda89690e8f7b"
    hash4       = "b018a121b8e8789de7517fa6d230827f537ccadbfc78e5888f41e4b02849bb77"
    hash5       = "978cbaa195d4647b16afbcb1bf5e85e03672d4345881770bb5f24bf2e6beb35b"
    hash6       = "7df0582dfc9b39225e3f5db2c9d707f392fa0cf96c440388bc97f792de260563"
    hash7       = "3cf2b5d1e973b29a24fb05f608046e483f008cd0861246bc6367c1507bb4a672"
    hash8       = "10d7db2ec1fa897b98373589c629e14b938d81a952bc33c32d60aea1522f86d6"
    hash9       = "b1912626b659a3e7c8d7003983de4bd630d893fdffdad0410f6517d380e2993d"
    hash10      = "606530060f3930854d6d0d23513f084de3bcb576f1959955d00b3cd67b8c7d60"
    hash11      = "0e379293c9b084834bbc33561278ec9c8df126ba38e99f79640d5e76a7838745"
    hash12      = "cca26baaa5fda68034cf93a1075ab828f249f8daab0a58b96f7ab3f0ef7f6e0a"

  strings:
    $s1  = "Failed to create file mapping %s, error %u" fullword ascii
    $s2  = "Failed to open %s, error %u" fullword ascii
    $s3  = "Partial stub ignores passwords" fullword ascii
    $s4  = "(%p, %s, %s): partial stub" fullword ascii
    $s5  = "no space for user data size" fullword ascii
    $s6  = "no space for user data" fullword ascii
    $s7  = "User Data size %#x" fullword ascii
    $s8  = "signature version %04x, client version %04x" fullword ascii
    $s9  = "(%p, %d, %d): stub" fullword ascii
    $s10 = "(%p, %p): partial stub" fullword ascii
    $s11 = "(%p, %d, %p): stub" fullword ascii
    $s12 = "(%p, %d): stub" fullword ascii
    $s13 = "string %u: %s" fullword ascii
    $s14 = "(%p, %p, %d): stub" fullword ascii
    $s15 = "no space for reserved data size" fullword ascii
    $s16 = "no space for instance count" fullword ascii
    $s17 = "no space for triggers count" fullword ascii
    $s18 = "no space for reserved data" fullword ascii
    $s19 = "no space for signature" fullword ascii
    $s20 = "no space for triggers data" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}