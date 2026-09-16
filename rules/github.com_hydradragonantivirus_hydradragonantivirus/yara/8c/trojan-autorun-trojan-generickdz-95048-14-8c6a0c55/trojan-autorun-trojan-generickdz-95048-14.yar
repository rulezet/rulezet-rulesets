rule Trojan_Autorun_Trojan_GenericKDZ_95048_14 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.95048_14.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "99358e8b87fe72c635b5b5b4a8df0bdba46cd5e5e5ac1814b6a86164198e174d"

  strings:
    $s1 = "l;mArE?" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}