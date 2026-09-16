rule Virus_Hijack_GenPack_Backdoor_Hangup_B_48_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_48_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd221976d86d2fed4c2c7c15a2c348d54a00cac833ee7db47d265fa00e5f9d08"

  strings:
    $s1 = "lSaveGCConsentInfo::User consent saved successfully = " fullword wide
    $s2 = "CustomActionInfo: INFO: [IsAppRunningInReducedMode] : sEntitlementStatus not set to EXPIRED, not running in RM" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}