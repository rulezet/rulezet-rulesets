rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aCXl7mh {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aCXl7mh.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b95118fe24ae54b595c0092f3bf941f067fc6decd5faf1370c220eff3a99366"

  strings:
    $s1 = ".Orders: is defined as the total number of distinct orders for all programs that are a part of Electronic Orders, entered" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}