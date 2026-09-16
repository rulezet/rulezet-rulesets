rule Trojan_Autorun_Gen_Trojan_Backdoor2_zmZbaKq9kbjb_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Backdoor2.zmZbaKq9kbjb_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e1da941dd4a4af262f80d3b2cacad77e630877eaa85ea79a14247a21bb7adaa"

  strings:
    $s1 = "lSaveGCConsentInfo::User consent saved successfully = " fullword wide
    $s2 = "CustomActionInfo: INFO: [IsAppRunningInReducedMode] : sEntitlementStatus not set to EXPIRED, not running in RM" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}