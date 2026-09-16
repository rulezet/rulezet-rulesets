rule Virus_Autorun_Win32_Neshta_A_24 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_24.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a8e0771dc70b46c95319152a97c6952a996864473e3b6f18eb63f98a0e3fafc0"

  strings:
    $s1 = "@3Planesoft Live Wallpaper Helpe" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}