rule Virus_Injector_Win32_Worm_Viking_NDL_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Injector_Win32.Worm.Viking.NDL_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "599c48c750bd25431b1f691b04b0e8a3587e165b13ae51ea346ca05842aa2221"

  strings:
    $s1 = "]CRUx)" fullword ascii
    $s2 = "weNt&_" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}