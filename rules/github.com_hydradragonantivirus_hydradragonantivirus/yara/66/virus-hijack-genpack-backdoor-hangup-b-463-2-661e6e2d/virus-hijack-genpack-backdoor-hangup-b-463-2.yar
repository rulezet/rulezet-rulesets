rule Virus_Hijack_GenPack_Backdoor_Hangup_B_463_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_463_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce09e5a01601f2863a39987091052a89016e5fbe98fd93c968ac701a380c36fc"

  strings:
    $s1  = "/T:<full path> -- " fullword wide
    $s2  = "Windows NT 4.0 Beta 2 " fullword wide
    $s3  = "HTML input (chars).tdl" fullword ascii
    $s4  = "tex (base).tdl" fullword ascii
    $s5  = "Presentation MathML input.tdl" fullword ascii
    $s6  = "Texvc (Physics Forum).tdl" fullword ascii
    $s7  = "Texvc (LaTeX delimiters).tdl" fullword ascii
    $s8  = "plain tex.tdl" fullword ascii
    $s9  = "tex (ams base).tdl" fullword ascii
    $s10 = "Texvc input (chars).tdl" fullword ascii
    $s11 = "MathML2 (Maple).tdl" fullword ascii
    $s12 = "Type 0 def" fullword ascii
    $s13 = "lEAM>hJ" fullword ascii
    $s14 = "mOud;`G@\\" fullword ascii
    $s15 = "SeIT@KF" fullword ascii
    $s16 = ")MEnD,)x^H" fullword ascii
    $s17 = "uMbO?u" fullword ascii
    $s18 = "+*HeeR" fullword ascii
    $s19 = "(wALi`" fullword ascii
    $s20 = "j[siMA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}