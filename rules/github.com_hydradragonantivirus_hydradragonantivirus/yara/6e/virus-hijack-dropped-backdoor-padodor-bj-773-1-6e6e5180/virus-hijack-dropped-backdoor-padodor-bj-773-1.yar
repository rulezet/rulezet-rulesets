rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_773_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_773_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "befd929b1183942843586e9de654f812a49eb8108323405b5d2f449b99ffed99"

  strings:
    $s1 = "mendable" fullword wide
    $s2 = "Subabdominal" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}