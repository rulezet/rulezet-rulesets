rule Virus_Hijack_Trojan_GenericKDZ_105924_87_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_87_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ba11a38855050471608ebbdcbc8456fbd5d38a06a7fb52d96456fac0bf8cc2f"

  strings:
    $s1 = "sOMe]0" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}