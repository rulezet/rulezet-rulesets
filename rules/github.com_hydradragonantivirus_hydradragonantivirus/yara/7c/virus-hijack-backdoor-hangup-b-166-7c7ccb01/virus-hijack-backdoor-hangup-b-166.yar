rule Virus_Hijack_Backdoor_Hangup_B_166 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_166.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e236a965422821c27fce54758347c21eb10350fdc58b2dae8343c6e1468656d"

  strings:
    $s1 = "}your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}