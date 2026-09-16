rule Virus_Hijack_Gen_Trojan_ShellObject_pyZ_aeWgNZc_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.pyZ@aeWgNZc_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "816aeb1e939fe0bcd2dcc600e09e5204ff9522b53e57ee12136846750a11b0f6"

  strings:
    $s1 = "9%KOel" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}