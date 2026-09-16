import "pe"
rule _Virus_Hijack_Trojan_GenericKDZ_105924_161_1_Virus_Sysbot_GenPac_10 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Trojan.GenericKDZ.105924_161_1.vir, Virus.Sysbot_GenPack.Trojan.GenericKDZ.94923_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d95841aa2c9fd60765ae716bff955c9378344bcbb1be741a1b80d34c62030a05"
    hash2       = "265d5451c752f910f6def2339f07b36c6fcf4be14ad27a3b03e5bd513c843d71"

  strings:
    $s1 = " yeLl!_-W" fullword ascii
    $s2 = "COrA()" fullword ascii
    $s3 = "G:Sore)" fullword ascii
    $s4 = "OW%KOhl" fullword ascii
    $s5 = "safe>)" fullword ascii
    $s6 = "RAMPDS" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and (all of them)
    ) or (all of them)
}