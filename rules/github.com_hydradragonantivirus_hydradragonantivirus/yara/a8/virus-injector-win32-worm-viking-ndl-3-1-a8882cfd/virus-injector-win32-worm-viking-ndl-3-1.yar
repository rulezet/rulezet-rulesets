rule Virus_Injector_Win32_Worm_Viking_NDL_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Injector_Win32.Worm.Viking.NDL_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4df40dce4af90fded4bccbc42b209e00a731edc7de66fcb60ffd581a97d34b4"

  strings:
    $s1 = "rinG,/ " fullword ascii
    $s2 = "\"bunD]" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}