rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_638 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_638.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ffa7de5e16037fc70547726366f0c02f0ed1eacbc81444ec4f3a49bef4e23c4"

  strings:
    $s1 = "iYou may temporarily download the fonts to a prin" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}