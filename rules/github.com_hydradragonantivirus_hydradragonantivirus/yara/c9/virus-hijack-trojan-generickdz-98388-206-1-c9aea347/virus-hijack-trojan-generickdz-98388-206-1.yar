rule Virus_Hijack_Trojan_GenericKDZ_98388_206_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_206_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a57302483c23793c722ba24506b737ddfb45b6477e69076b0bdedc8af258801a"

  strings:
    $s1 = "]l\"[hEFT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}