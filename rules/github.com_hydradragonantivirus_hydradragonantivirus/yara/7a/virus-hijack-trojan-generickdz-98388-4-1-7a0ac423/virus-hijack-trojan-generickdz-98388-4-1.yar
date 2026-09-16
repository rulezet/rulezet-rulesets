rule Virus_Hijack_Trojan_GenericKDZ_98388_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22b792e4f3405b7ba395f921751c54c8bf127d16896d7fde3eee0bc36d4f485f"

  strings:
    $s1 = "/>oimE" fullword ascii
    $s2 = "[&GRid" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}