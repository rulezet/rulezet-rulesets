rule Virus_Hijack_Gen_Trojan_ShellObject_E8Z_a41ciQg_12_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.E8Z@a41ciQg_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2198f5dc6d49a4f76d0db778febc74ef6a880936340fa6038a552324503eb859"

  strings:
    $x1  = "echo 75.127.83.69  www.bancodebogota.com  >>%windir%\\System32\\drivers\\etc\\hosts" fullword ascii
    $x2  = "echo 75.127.85.130 www.colmena.com.co   >>%windir%\\System32\\drivers\\etc\\hosts" fullword ascii
    $x3  = "echo 75.127.85.130 colmena.com   >>%windir%\\System32\\drivers\\etc\\hosts" fullword ascii
    $x4  = "echo 75.127.85.130 www.colmena.com   >>%windir%\\System32\\drivers\\etc\\hosts" fullword ascii
    $x5  = "echo 75.127.85.130 en-linea.colmena.com.co   >>%windir%\\System32\\drivers\\etc\\hosts" fullword ascii
    $x6  = "echo 75.127.83.69  www.bancodebogota.com.co   >>%windir%\\System32\\drivers\\etc\\hosts" fullword ascii
    $x7  = "echo 75.127.83.69  bancodebogota.com.co   >>%windir%\\System32\\drivers\\etc\\hosts" fullword ascii
    $x8  = "echo 75.127.85.130 enlineaempresarialcolmena.com.co   >>%windir%\\System32\\drivers\\etc\\hosts" fullword ascii
    $x9  = "echo 75.127.83.69  bancodebogota.com   >>%windir%\\System32\\drivers\\etc\\hosts" fullword ascii
    $x10 = "echo 75.127.85.130 colmena.com.co   >>%windir%\\System32\\drivers\\etc\\hosts" fullword ascii
    $s11 = "copy hosts c:\\WINDOWS\\system32\\drivers\\etc\\hosts" fullword ascii
    $s12 = "batfile.bat                                                                                         @echo off " fullword ascii
    $s13 = "echo > \"" fullword ascii
    $s14 = "title LOLOLOLO01000122112210111" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}