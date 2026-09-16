import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_f8X_aian2n_6_2_Virus_Hijack_201 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_6_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_7_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_9_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d69c7020eeb7de540f830d03515ec2250e38ea65d3d07c193cdceab91690352c"
    hash2       = "7b5dba2433e75e52593ad7d997ecb1578d0b826f70297839c667c283abe1cabe"
    hash3       = "36c493955e1cec5dd730bb2569f174e248447dea2705ee3e86e22cdbfe2078fa"

  strings:
    $s1  = "PROCESSOR IDENTIFIER : %s" fullword ascii
    $s2  = "LOGON SERVER : %s" fullword ascii
    $s3  = "ALL USERS PROFILE : %s" fullword ascii
    $s4  = "Flash&Media.lnk" fullword ascii
    $s5  = "Kaspersky Internet Security 2012.lnkOFFICE2007.lnk" fullword ascii
    $s6  = "MailOu At This Computer Name : %s" fullword ascii
    $s7  = "COM SPEC : %s" fullword ascii
    $s8  = "MODE : COM7" fullword ascii
    $s9  = "USER DOMAIN : %s" fullword ascii
    $s10 = "USER NAME : %s" fullword ascii
    $s11 = "USER PROFILE : %s" fullword ascii
    $s12 = "Error number 909:" fullword ascii
    $s13 = "the shade love you so so much" fullword ascii
    $s14 = "PATH EXT : %s" fullword ascii
    $s15 = "MODE : default" fullword ascii
    $s16 = "Getting the kLevel ..." fullword ascii
    $s17 = "MODE : ashcv" fullword ascii
    $s18 = "the shade doesn't want you death" fullword ascii
    $s19 = "HOME PATH : %s" fullword ascii
    $s20 = "Peace On You." fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "ea28f662ab831803e9a8c823439760d0" and (8 of them)
    ) or (all of them)
}