rule Virus_Hijack_Trojan_GenericKDZ_105924_536_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_536_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a89c293589424b86f393cc95b7da78301efc717f5c6f81b6072f93d6c2de632"

  strings:
    $s1 = "HeEr&N" fullword ascii
    $s2 = "liFO[B" fullword ascii
    $s3 = "J>pAnK" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}