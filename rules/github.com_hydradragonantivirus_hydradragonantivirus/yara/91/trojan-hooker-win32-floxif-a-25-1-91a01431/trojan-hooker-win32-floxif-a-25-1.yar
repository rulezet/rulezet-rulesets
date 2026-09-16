rule Trojan_Hooker_Win32_Floxif_A_25_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_25_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "10f590483b186da3c9ca8c2db7683a69ce1625b30ba8cfc49d80c1665620db77"

  strings:
    $s1 = "FILE FOLDER*" fullword ascii
    $s2 = "?sOMA%#R60" fullword ascii
    $s3 = "@Clean" fullword ascii
    $s4 = "5t Visual Audio\\1C'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}