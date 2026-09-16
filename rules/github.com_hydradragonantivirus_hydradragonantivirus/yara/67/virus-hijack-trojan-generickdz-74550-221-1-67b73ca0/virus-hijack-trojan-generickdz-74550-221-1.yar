rule Virus_Hijack_Trojan_GenericKDZ_74550_221_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_221_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ffe44d30d85bbf6ba34edf5b007a1d95662330a06b921410ea4b762dbafad6b"

  strings:
    $s1 = "[[cuRD" fullword ascii
    $s2 = "KUGE.bp" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}