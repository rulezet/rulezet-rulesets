rule Virus_Hijack_Trojan_Agent_DQQO_139_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_139_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87c26f81593bb0f5262b568308413924c4a8542c61ca88037991fd07c55fa562"

  strings:
    $s1 = "\\Usb 2.0 Driver" fullword wide
    $s2 = "Usb 2.0 Driver" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}