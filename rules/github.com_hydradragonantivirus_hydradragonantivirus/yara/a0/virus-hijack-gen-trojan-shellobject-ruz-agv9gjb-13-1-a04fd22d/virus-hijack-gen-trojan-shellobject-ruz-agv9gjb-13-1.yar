rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_aGV9gJb_13_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aGV9gJb_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6482e06331224f3ca54f9315de95911241870cf18129d2e18aaaf8aaa6bdda3"

  strings:
    $s1 = "@h{SkIm" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}