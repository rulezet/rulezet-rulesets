rule Virus_Hijack_Trojan_GenericKDZ_105924_430_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_430_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "322aab7f4c37dd3893199e4e46b8e6478ed6852e5c5e10437ce5fd6af91cc72b"

  strings:
    $s1 = "tumP?D" fullword ascii
    $s2 = "\\n<FaCE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}