rule Virus_Hijack_Trojan_Agent_DQQO_146 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_146.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4beb3cd1d64c89d0599787c46e9851bae071eb7060d7fbc381dcdbc3fd77069f"

  strings:
    $s1 = "FOrders: is defined as the total number of distinct orders for all programs that are a part of Electronic Orders, entered" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}