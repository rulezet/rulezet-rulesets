rule Virus_Hijack_Gen_Trojan_ShellObject_m8W_aW0I0Cd_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8W@aW0I0Cd_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e19ed8e05eb99e5af2cf0b379a05cbf9e1e9be41f78206ef102d84c50eb0c434"

  strings:
    $s1 = "KeRn$;" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}