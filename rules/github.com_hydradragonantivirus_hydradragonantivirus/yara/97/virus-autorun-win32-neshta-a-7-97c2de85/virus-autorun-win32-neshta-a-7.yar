rule Virus_Autorun_Win32_Neshta_A_7 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "331b31c58dad5c1e6f92622585c2aa05668723efc6ebacc716d2ab927e32a821"

  strings:
    $s1 = "ANGLE (Intel, Intel(R) HD Graphics 620 (0x00005916) Direct3D11 vs_5_0 ps_5_0, D3D11-27.20.100.9664)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}