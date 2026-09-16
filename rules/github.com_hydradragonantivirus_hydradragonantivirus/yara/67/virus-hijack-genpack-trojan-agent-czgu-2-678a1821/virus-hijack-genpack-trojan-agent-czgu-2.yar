rule Virus_Hijack_GenPack_Trojan_Agent_CZGU_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Trojan.Agent.CZGU_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0db08f317e7ca5c5aa8b451f9102c3b121c5f6de11fb842850d2485ce49f775f"

  strings:
    $s1 = "gram FU" fullword ascii
    $s2 = "Module@1" fullword ascii
    $s3 = "CRITIC" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}