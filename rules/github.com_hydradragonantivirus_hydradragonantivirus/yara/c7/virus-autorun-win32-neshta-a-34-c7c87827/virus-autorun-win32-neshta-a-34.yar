rule Virus_Autorun_Win32_Neshta_A_34 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_34.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a4bb8850d707c24fa7aea0410d520879334dbf6736e0250579c205c2f0d35f57"

  strings:
    $s1 = "Change current dir to <%s>" fullword ascii
    $s2 = "Reduce add reserved space %lldMB" fullword ascii
    $s3 = "Change GPT partition attribute" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}