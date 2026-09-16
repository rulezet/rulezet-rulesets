import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_f8X_aian2n_6_2_Virus_Hijack_381 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_6_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_7_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_8_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_9_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d69c7020eeb7de540f830d03515ec2250e38ea65d3d07c193cdceab91690352c"
    hash2       = "7b5dba2433e75e52593ad7d997ecb1578d0b826f70297839c667c283abe1cabe"
    hash3       = "9d5274e6a7633f0ac58c5af7d79d93f92740ac728aaa5d20019f036515371a41"
    hash4       = "36c493955e1cec5dd730bb2569f174e248447dea2705ee3e86e22cdbfe2078fa"

  strings:
    $s1 = "PDF Reader Launcher.exe" fullword ascii
    $s2 = "POST %s?mode=%s&usr=%s HTTP/1.1" fullword ascii
    $s3 = "Movie Maker.lnk" fullword ascii
    $s4 = "Alcohol Soft.lnk" fullword ascii
    $s5 = "Norton Internet Security 2012.lnk" fullword ascii
    $s6 = "PDF Reader Launcher" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "ea28f662ab831803e9a8c823439760d0" and (all of them)
    ) or (all of them)
}