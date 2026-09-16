rule Virus_Hijack_Trojan_GenericKDZ_105924_164_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_164_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29c190fa460b68d5e5185990b98d1411e293d33b48ec86404aa9743e8e766e29"

  strings:
    $s1  = "<Server> LiveKeylogger START." fullword ascii
    $s2  = "<Server> LiveKeylogger END." fullword ascii
    $s3  = "set cdaudio door closed" fullword ascii
    $s4  = "shutdown -s -t 1 -f" fullword ascii
    $s5  = "shutdown -r -t 1 -f" fullword ascii
    $s6  = "set cdaudio door open" fullword ascii
    $s7  = "<Server> Script." fullword ascii
    $s8  = "<Server> GetInfo." fullword ascii
    $s9  = "<Server> Mouse&Keyboard unlock." fullword ascii
    $s10 = "<Server> Mouse&Keyboard block." fullword ascii
    $s11 = "<Client> Connessione persa" fullword ascii
    $s12 = "<Client> Connesso con il Server!" fullword ascii
    $s13 = "<Server> Client hide." fullword ascii
    $s14 = "<Server> TPC." fullword ascii
    $s15 = "<Server> Mouse swap." fullword ascii
    $s16 = "<Server> MouseUnviber." fullword ascii
    $s17 = "<Server> Shutdown." fullword ascii
    $s18 = "<Server> Mouse unswap." fullword ascii
    $s19 = "<Server> Client restart." fullword ascii
    $s20 = "<Server> Clock Show." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}