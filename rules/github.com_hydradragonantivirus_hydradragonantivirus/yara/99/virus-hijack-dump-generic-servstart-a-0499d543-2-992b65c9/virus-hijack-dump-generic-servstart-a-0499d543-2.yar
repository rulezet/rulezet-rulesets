rule Virus_Hijack_Dump_Generic_ServStart_A_0499D543_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dump.Generic.ServStart.A.0499D543_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1423d7d7ee914332aaf5b0c8a0801722d811dfeb92af60536bbbb36ecbcec18"

  strings:
    $s1 = "Semielision" fullword wide
    $s2 = "Serpentinic" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}