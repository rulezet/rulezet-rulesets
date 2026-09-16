rule Virus_Hijack_Win32_Grenam_G_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Win32.Grenam.G_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5054f720fa4cb3325cf5d98e344ac12dd64d0ac05491014b37c7d24114c24ba"

  strings:
    $s1 = "Orientation,%B" fullword ascii
    $s2 = "Color@'B" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}