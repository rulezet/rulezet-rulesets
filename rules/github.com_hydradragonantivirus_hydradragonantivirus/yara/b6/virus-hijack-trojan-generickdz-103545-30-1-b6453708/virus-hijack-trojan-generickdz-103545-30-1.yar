rule Virus_Hijack_Trojan_GenericKDZ_103545_30_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_30_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5066d381cd20ce123fae6d721fd6c83cfd3b1ffe843e334de75526546d5e0c9e"

  strings:
    $s1 = "h]MulK" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}