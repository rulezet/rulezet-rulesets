rule Virus_Sysbot__Trojan_GenericKD_71671752_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot _Trojan.GenericKD.71671752_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b33ee3b0f048741c7b4b558559b76415347fb4474143cf017e5c52b37bf9173"

  strings:
    $s1 = "(:MaSH" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}