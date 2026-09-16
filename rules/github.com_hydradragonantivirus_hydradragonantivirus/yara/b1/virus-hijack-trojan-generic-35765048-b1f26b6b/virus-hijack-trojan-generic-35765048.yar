rule Virus_Hijack_Trojan_Generic_35765048 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Generic.35765048.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e85773ba97cd618e9c309eef5dd2421e500482a08918b8e6199329a4a1722149"

  strings:
    $s1 = ")^!sHER" fullword ascii
    $s2 = "U?bAnE,KQ" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}