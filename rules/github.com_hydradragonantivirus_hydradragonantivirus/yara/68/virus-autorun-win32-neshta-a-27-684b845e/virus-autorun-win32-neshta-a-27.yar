rule Virus_Autorun_Win32_Neshta_A_27 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_27.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b50c7bebfebb3e112e2cb63fef67076699d6e18ef713093f766696bc3529721"

  strings:
    $s1 = "USB Receiver" fullword wide
    $s2 = "CORBEL BOLD ITALIC" fullword wide
    $s3 = "CORBEL ITALIC" fullword wide
    $s4 = "COURIER NEW NEGRITA CURSIVA" fullword wide
    $s5 = "COURIER NEW NEGRITA" fullword wide
    $s6 = "CORBEL LIGHT" fullword wide
    $s7 = "CORBEL BOLD" fullword wide
    $s8 = "CORBEL LIGHT ITALIC" fullword wide
    $s9 = "COURIER NEW" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}