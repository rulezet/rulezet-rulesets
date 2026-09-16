rule Trojan_Hooker_Win32_Floxif_A_6 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b37e91dff02d701a772d4a491f6fcff65597f540d4b6fee01bdeb035f3b4f27"

  strings:
    $s1 = "Ashampoo Driver Updater.exe" fullword wide
    $s2 = "Ashampoo Driver Updater" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}