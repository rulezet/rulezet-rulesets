rule Virus_Hijack_GenPack_Backdoor_Hangup_B_194 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_194.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9516db09d9d56cc3a0d362e8b3b38cf039cfc961d3fb6710fe4031a3b8714280"

  strings:
    $s1 = "Iof the software and a separate license for each copy. Content protected by digital rights management" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}