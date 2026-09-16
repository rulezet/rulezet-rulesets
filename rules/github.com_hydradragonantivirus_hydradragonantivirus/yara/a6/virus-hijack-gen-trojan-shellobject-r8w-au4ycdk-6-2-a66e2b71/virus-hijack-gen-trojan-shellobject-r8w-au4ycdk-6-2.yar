rule Virus_Hijack_Gen_Trojan_ShellObject_r8W_au4YcDk_6_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.r8W@au4YcDk_6_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38ff4b2cf9d7993378ae67e035275f74513bdf7a4c7db6ab4f12a12f2bbf9160"

  strings:
    $x1  = "Coded and (c) Speed Guide, Inc. - webmaster@speedguide.net / outsorcing@gmail.com" fullword wide
    $s2  = "The current user account does not have permissions to change all necessary settings. Please start the program with administrator" wide
    $s3  = "{\\title Copyright \\'a9 2015 Speed Guide, Inc}{\\author RWaters}{\\operator ilko}{\\creatim\\yr2005\\mo3\\dy24\\hr12\\min7}{\\r" ascii
    $s4  = "The largest possible non-fragmented packet is %d  (%d - 28 ICMP & IP headers)." fullword ascii
    $s5  = "(default varies, recommended: CUBIC or CTCP)]Reduces networking-related CPU overhead by offloading all TCP processing to a netwo" wide
    $s6  = "Reserved percent of CPU resources for background processes  (defaul: 20, recommended: 10 for general apps, 0 for pure gaming/str" ascii
    $s7  = "Reserved percent of CPU resources for background processes  (defaul: 20, recommended: 10 for general apps, 0 for pure gaming/str" ascii
    $s8  = "The current user account does not have permission to write to all the necessary Registry hives. Please login with administrator " wide
    $s9  = "command failed" fullword ascii
    $s10 = "avi1D3.tmp.avi Video #1" fullword ascii
    $s11 = "ACK Interval timeout - only has effect if nagling is enabled (default: n/a, recommended: n/a, to disable nagling set to: 0)" fullword ascii
    $s12 = "Copy key name to clipboardKFor IE browsers only - the number of concurrent connections to a Web serverKFor IE browsers only - th" wide
    $s13 = "{\\title Copyright \\'a9 2015 Speed Guide, Inc}{\\author RWaters}{\\operator ilko}{\\creatim\\yr2005\\mo3\\dy24\\hr12\\min7}{\\r" ascii
    $s14 = "Number of times to attempt to reestablish a connection with SYN packets" fullword ascii
    $s15 = "%s\\%s\\%s  ->  Access dinied " fullword ascii
    $s16 = "t. Speed Guide, Inc. may offer online support via http://www.speedguide.net at its sole discretion." fullword ascii
    $s17 = "Speed Guide, Inc. has no obligation to support or upgrade the Software, or assist in the use of the Software under this Agreemen" ascii
    $s18 = "Connection Speed  %s:" fullword ascii
    $s19 = "The packet size must be between : 1 - 1500" fullword ascii
    $s20 = "The pings per URL must be between : 1 - 9" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}