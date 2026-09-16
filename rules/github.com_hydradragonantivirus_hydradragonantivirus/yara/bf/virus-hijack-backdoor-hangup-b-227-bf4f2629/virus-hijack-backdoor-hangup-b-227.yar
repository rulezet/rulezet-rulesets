rule Virus_Hijack_Backdoor_Hangup_B_227 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_227.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62fb88cbe4278618241abdb43aef7eec7140035a8080ee68c1fbea780ff46b2c"

  strings:
    $s1 = "$of the software and a separate license for each copy. Content protected by digital rights management" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}