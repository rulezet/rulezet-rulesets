rule Trojan_Autorun_Trojan_Ransom_Doboc_A_13 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.Ransom.Doboc.A_13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79d2c85b03bc6fa02f10d41efa69832cc5e5a5246d0b09308aa8865763f470d9"

  strings:
    $s1 = "sArpo)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}