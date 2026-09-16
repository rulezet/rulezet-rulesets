rule Virus_Hijack_Trojan_GenericKDZ_74550_102_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_102_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9768f23783542e0fc5e100a3ff478884cfe0b25732749183a0e56cc7ec509ed5"

  strings:
    $s1 = "TuIK.}9" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}