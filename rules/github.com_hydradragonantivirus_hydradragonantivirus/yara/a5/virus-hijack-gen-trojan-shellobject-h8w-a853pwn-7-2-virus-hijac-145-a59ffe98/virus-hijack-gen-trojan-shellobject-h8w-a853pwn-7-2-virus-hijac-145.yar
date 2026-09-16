rule _Virus_Hijack_Gen_Trojan_ShellObject_h8W_a853Pwn_7_2_Virus_Hijac_145 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.h8W@a853Pwn_7_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@aCZnhbe_10_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@aCZnhbe_2_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@aCZnhbe_4_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@aCZnhbe_6_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@aCZnhbe_9_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@aqG68Ic_5_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@auCCoZb_2_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@auCCoZb_8_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8X@a0kuefc_5_2.vir, VirusShareTrojanClick257946_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c682e361f77ae05470a76065c7a3641d40a2707ab5bece61798a7542d7b48a04"
    hash2       = "9e68803ee118256c8a1729b7d1f0b761ccdfd50cff611cfcd9d98f879a15410e"
    hash3       = "cea0f6579e0a9fc4f65c6d764a391e16713718b2ae8f9d02ec0b5aab0052f275"
    hash4       = "8ffc22831e7cc7f8347786df680a1e88334870291eaba78062c7ed10ea78b48b"
    hash5       = "fcfa5783774e74956d95e0deedf9d25babe25559d2ba4e81addbda1b4a626f52"
    hash6       = "7302e964793f853740b92325b2308b5537a880881a4acd99e6cb5ffbddc300ae"
    hash7       = "d470656d006564f0f5d23c44f21c3633a8eb677c2906888e48b52df716020f64"
    hash8       = "c1f695c43e223422681b9db47bacb1180d4b32317eb12214b115efca6b3d3cc7"
    hash9       = "ec9db3112adce1d4c63aecf111590d20cec1642c9fd8c8c5f975ae0253c6afd1"
    hash10      = "874c2e6f552ddd05c4a2f51a7859422bdb36992ab31f92480f15a355eaf799f8"
    hash11      = "2232141d329267f88679decd77f3992b67862e751aa2deaa6585cf8116eddeda"

  strings:
    $s1  = "/Title (1.2. Automake in the autotools process)" fullword ascii
    $s2  = "acute /icircumflex /idieresis /eth /ntilde /ograve /oacute /ocircumflex /otilde /odieresis /divide /oslash /ugrave /uacute /ucir" ascii
    $s3  = "tilde /Adieresis /Aring /AE /Ccedilla /Egrave /Eacute /Ecircumflex /Edieresis /Igrave /Iacute /Icircumflex /Idieresis /Eth /Ntil" ascii
    $s4  = "cute /icircumflex /idieresis /eth /ntilde /ograve /oacute /ocircumflex /otilde /odieresis /divide /oslash /ugrave /uacute /ucirc" ascii
    $s5  = "sand /quoteright /parenleft /parenright /asterisk /plus /comma /hyphen /period /slash /zero /one /two /three /four /five /six /s" ascii
    $s6  = "/Title (Contents)" fullword ascii
    $s7  = "even /eight /nine /colon /semicolon /less /equal /greater /question /at /A /B /C /D /E /F /G /H /I /J /K /L /M /N /O /P /Q /R /S" ascii
    $s8  = "slash /.notdef /exclamdown /cent /sterling /currency /yen /brokenbar /section /dieresis /copyright /ordfeminine /guilsinglleft /" ascii
    $s9  = "/Creator (groff version 1.22.4)" fullword ascii
    $s10 = "/Producer (gropdf version 1.22.4)" fullword ascii
    $s11 = "/Title (1.1. First build)" fullword ascii
    $s12 = "/Title (3.1. 1st possibility: make recursion)" fullword ascii
    $s13 = "/Title (3. Non-recursive make schema)" fullword ascii
    $s14 = "/Title (2. Building a program)" fullword ascii
    $s15 = "/Title (5. Extending Automake's rules)" fullword ascii
    $s16 = "/Title (1. Overview, the initial build)" fullword ascii
    $s17 = "/Title (4. Installing data)" fullword ascii
    $s18 = "/Title (4.2. Dealing with generated files)" fullword ascii
    $s19 = "/Title (3.2. Non-recursive make used by the Groff project)" fullword ascii
    $s20 = "/Title (2.2. Linking against a library)" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}