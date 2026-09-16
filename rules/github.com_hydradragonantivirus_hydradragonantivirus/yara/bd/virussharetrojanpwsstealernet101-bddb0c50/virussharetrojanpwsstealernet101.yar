rule VirusShareTrojanPWSStealerNET101 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanPWSStealerNET101.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9ed037580f9db1b3331de0335dc1af3456177c84aa24dac9b64c599a27542c3"

  strings:
    $s1 = "GAnE,NOQ'3" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}