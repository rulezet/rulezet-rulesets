rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aG5Bc5o_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2943adf1d1a7d233859baf9675bb4f87eb1ab14685ca7f79919429f27684d033"

  strings:
    $s1  = "d:\\Program Files\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii
    $s2  = "CreateRemoteThread Success" fullword ascii
    $s3  = "d:\\Program Files\\Microsoft Visual Studio\\VB98\\shdocvw.oca" fullword ascii
    $s4  = " your application. It is most likely the result of calling an MSIL-compiled (/clr) function from a native constructor or from Dl" ascii
    $s5  = "mute chrome" fullword wide
    $s6  = "`dynamic atexit destructor f" fullword ascii
    $s7  = "CreateSoundBuffer Success" fullword ascii
    $s8  = "Hook_DirectSoundCreate Success" fullword ascii
    $s9  = "Hook_DirectSoundCreate8 Success" fullword ascii
    $s10 = "Copyright (C) 20" fullword wide
    $s11 = " your application. It is most likely the result of calling an MSIL-compiled (/clr) function from a native constructor or from Dl" ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}