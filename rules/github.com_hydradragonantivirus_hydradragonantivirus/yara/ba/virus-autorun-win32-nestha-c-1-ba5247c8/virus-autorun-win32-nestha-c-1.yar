rule Virus_Autorun_Win32_Nestha_C_1 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Nestha.C_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ac3f4ca460d633f2fde571c712607b12164d991fa7176804483bd047a123c4d"

  strings:
    $s1 = "Combine filesAAcrobat quit unexpectedly. Click 'Learn more' for possible fixes.2http://www.adobe.com/go/fix_acrobat_launch_crash" wide
    $s2 = "/PRODUCT:Acrobat /VERSION:24.0 /MODE:" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}