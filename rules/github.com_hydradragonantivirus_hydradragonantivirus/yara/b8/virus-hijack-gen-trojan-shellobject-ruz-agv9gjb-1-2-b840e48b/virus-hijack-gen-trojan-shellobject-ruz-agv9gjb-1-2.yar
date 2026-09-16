rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_aGV9gJb_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aGV9gJb_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7813b6f9cd03b0641047b6bcc969403cef12fe3b461c6907777a3eaf710571fe"

  strings:
    $s1  = "The process returned an error" fullword wide
    $s2  = "This program only runs on Windows XP or later versions of Windows (%d.%d/%d)" fullword wide
    $s3  = "Error reading report" fullword wide
    $s4  = "contact@ninite.com0" fullword ascii
    $s5  = "Connection error (name not resolved)" fullword wide
    $s6  = "The computer's date is set incorrectly (%04d-%02d-%02d)" fullword wide
    $s7  = "Range: bytes=%I64d-%I64d" fullword wide
    $s8  = "Please run in non-silent mode or go to " fullword wide
    $s9  = "Invalid data (1)(%d)(%d)" fullword wide
    $s10 = "Ninite Service" fullword wide
    $s11 = "Error launching Ninite: %ws" fullword wide
    $s12 = "Could not find key" fullword wide
    $s13 = "/stub:service" fullword wide
    $s14 = "An error occurred. " fullword wide
    $s15 = " for more information" fullword wide
    $s16 = "Could not get certificate" fullword wide
    $s17 = "Copyright (C) 2009 Secure By Design Inc" fullword wide
    $s18 = "Secure By Design Inc.1" fullword ascii
    $s19 = "Could not verify signature" fullword wide
    $s20 = "Could not open directory " fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}