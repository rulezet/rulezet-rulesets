rule Virus_Hijack_Trojan_GenericKDZ_105924_386_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_386_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc1e39d6f0c9fe2a240ed6cbd812dd4c391bf8a2fda7f93da2b096faed1738a0"

  strings:
    $s1 = "rasH}?" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}