rule Virus_Hijack_Trojan_GenericKDZ_74550_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1217d612dfe2ab535169fa797f409324e5025a5aa0a458f3e74471d518ee8fb"

  strings:
    $s1 = "YOLK m|" fullword ascii
    $s2 = "kAneh{" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}