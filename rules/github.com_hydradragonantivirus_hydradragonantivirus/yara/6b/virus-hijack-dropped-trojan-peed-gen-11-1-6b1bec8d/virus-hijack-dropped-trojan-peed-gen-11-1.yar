rule Virus_Hijack_Dropped_Trojan_Peed_Gen_11_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Trojan.Peed.Gen_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d49d8ebb6bce65a024dedd7dc5e80b581fb68856185fd867592cbcdaa045da4"

  strings:
    $s1 = "Allo7ation too large or negative: %u bytes." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}