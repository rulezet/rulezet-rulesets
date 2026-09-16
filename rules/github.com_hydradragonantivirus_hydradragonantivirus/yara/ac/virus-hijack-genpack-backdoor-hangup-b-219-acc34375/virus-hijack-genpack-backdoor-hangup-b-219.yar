rule Virus_Hijack_GenPack_Backdoor_Hangup_B_219 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_219.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a6de6afdad4b0fefe18b5dbc1fb222ef8ad27721f838a5e93cb0b211d5f3bf16"

  strings:
    $s1 = ")Jyour entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}