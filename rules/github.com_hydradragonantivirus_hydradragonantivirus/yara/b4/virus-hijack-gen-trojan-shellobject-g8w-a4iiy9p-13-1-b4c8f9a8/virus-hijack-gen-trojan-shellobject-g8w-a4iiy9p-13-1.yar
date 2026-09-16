rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_a4IIY9p_13_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@a4IIY9p_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7b34af6d917f7293edec5fc2785317400897ab503ce8ebab55eb6a5f8fa21ac"

  strings:
    $s1 = "buoy$9" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}