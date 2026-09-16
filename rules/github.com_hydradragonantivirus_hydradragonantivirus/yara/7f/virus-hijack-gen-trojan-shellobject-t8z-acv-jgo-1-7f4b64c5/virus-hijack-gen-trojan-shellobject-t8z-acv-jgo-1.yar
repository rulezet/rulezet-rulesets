rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_aCV_JGo_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@aCV@JGo_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17dc9bf03a2b5d3996fd06b908b0adfdcde5445af96d5a4249696a776982736b"

  strings:
    $s1 = "WJvirtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}