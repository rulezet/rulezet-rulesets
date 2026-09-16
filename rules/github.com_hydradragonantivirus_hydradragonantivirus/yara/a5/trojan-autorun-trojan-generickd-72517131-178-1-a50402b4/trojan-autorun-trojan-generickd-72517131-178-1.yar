rule Trojan_Autorun_Trojan_GenericKD_72517131_178_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_178_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0987d9e6e8221df44eb694f5371f3687092e76b44f71286e3055ee31134363d1"

  strings:
    $s1 = "]User, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}