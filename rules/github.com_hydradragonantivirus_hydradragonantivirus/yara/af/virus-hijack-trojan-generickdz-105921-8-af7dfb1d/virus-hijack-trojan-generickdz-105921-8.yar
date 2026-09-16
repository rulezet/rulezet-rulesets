rule Virus_Hijack_Trojan_GenericKDZ_105921_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105921_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d712cf4bf31975d01294108f2de22a0273c3ccb7ce73e4a1507a68d282da8443"

  strings:
    $s1 = "informational links in this agreement. The links containing terms that bind you and`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}