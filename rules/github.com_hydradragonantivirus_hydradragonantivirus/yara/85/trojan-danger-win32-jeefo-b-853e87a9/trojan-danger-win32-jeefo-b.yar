rule Trojan_Danger_Win32_Jeefo_B {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Win32.Jeefo.B.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef4c4c51a64df8114378100bc7c7d99a3d9361bec43b65ca3d08b055e8168968"

  strings:
    $s1 = "Internal Compiler Bug: No runtime type matcher." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}