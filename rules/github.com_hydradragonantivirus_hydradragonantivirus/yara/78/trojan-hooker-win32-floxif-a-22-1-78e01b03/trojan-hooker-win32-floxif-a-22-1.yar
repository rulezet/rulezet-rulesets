rule Trojan_Hooker_Win32_Floxif_A_22_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_22_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79b04c6db16db293c2c1267878ccf038325e82b6baf27222bc49f15b76b71943"

  strings:
    $s1 = "FILE FOLDER*" fullword ascii
    $s2 = "?sOMA%#R60" fullword ascii
    $s3 = "@Clean" fullword ascii
    $s4 = "5t Visual Audio\\1C'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}