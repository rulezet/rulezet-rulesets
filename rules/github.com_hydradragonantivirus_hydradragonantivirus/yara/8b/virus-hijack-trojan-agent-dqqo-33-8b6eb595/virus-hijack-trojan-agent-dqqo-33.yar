rule Virus_Hijack_Trojan_Agent_DQQO_33 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_33.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f817af3834055911bc6c2e8a005bb4c4b3827f117db1e5fccbf3ae8e620bcfbe"

  strings:
    $s1 = "; Professional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}