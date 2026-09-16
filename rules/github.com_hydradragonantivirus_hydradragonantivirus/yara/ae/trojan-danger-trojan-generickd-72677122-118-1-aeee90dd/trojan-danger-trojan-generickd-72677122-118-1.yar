rule Trojan_Danger_Trojan_GenericKD_72677122_118_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_118_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "899c54bcad18d779f100ee9918dfee58e1d61cbce83ec06ec760d911dc42d834"

  strings:
    $x1  = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
    $s2  = "Your disk have a lock!!!Please enter the unlock password" fullword ascii
    $s3  = "Delay Load Import Descriptors" fullword wide
    $s4  = "Bound Import Directory in headers" fullword wide
    $s5  = "Load Configuration Directory" fullword wide
    $s6  = "Unlocking the computer requires 30 RMB" fullword ascii
    $s7  = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\Boot file system\\" fullword ascii
    $s8  = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\Boot file system\\" fullword ascii
    $s9  = "Copyright (c) J.S.A.Kapp 1994." fullword ascii
    $s10 = "Architecture Specific Data" fullword wide
    $s11 = "Security Directory" fullword wide
    $s12 = "SECURE APPLICATION DEVELOPMENT1)0'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}