rule Trojan_Danger_Trojan_Generic_36486627_9 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.Generic.36486627_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0d87d74019fea05800fbf80309a399f5d7fe0446fa6fd3155f8f8b43ef3f0ff"

  strings:
    $s1 = "feLt*d" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}