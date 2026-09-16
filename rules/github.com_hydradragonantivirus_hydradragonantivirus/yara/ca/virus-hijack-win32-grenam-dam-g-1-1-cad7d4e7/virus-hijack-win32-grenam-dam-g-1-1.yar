rule Virus_Hijack_Win32_Grenam_Dam_G_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Win32.Grenam.Dam.G_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c863c64bd07f946fc1a078048af55a35623161a6e3a445d03ba784b454e55008"

  strings:
    $s1 = "AMir!ju" fullword ascii
    $s2 = "YR!achE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}