rule Virus_Sysbot_Dump_Generic_Dialer_BC6FFEAD_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.BC6FFEAD_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be6fec297c5d4c6b1e84438a42d12573f40e6fb606e994553849a335c5d66f1b"

  strings:
    $s1 = "g\"WANd" fullword ascii
    $s2 = "N*lerp" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}