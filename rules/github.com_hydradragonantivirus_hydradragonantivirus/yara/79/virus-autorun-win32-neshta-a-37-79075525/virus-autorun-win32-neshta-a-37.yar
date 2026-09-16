rule Virus_Autorun_Win32_Neshta_A_37 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_37.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "75c40df21e3dcafbe4e5d475151769119aff8558d70b1fd3c051f18547ad4ee9"

  strings:
    $s1 = "Correo: Luis Manuel - Outlook" fullword wide
    $s2 = "de estado de la pc~" fullword ascii
    $s3 = "de memoria de windows~" fullword ascii
    $s4 = "defender firewall con seguridad avanzada~" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}