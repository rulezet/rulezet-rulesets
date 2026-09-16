rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aGAMRTl_16_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aGAMRTl_16_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed003bb5d41b65c07c8d693fe324a58ac1b5ef76332c761aa82d8fb09b7b0dec"

  strings:
    $s1 = "Brave Software1" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}