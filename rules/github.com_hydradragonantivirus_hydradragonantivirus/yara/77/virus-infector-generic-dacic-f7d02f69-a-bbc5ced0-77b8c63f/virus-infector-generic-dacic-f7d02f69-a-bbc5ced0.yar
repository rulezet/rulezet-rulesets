rule Virus_Infector_Generic_Dacic_F7D02F69_A_BBC5CED0 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Generic.Dacic.F7D02F69.A.BBC5CED0.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9df7da5f808bc4925fe1b63b03cd1fbb5d844ebd432379fdb37d09e1182cef87"

  strings:
    $s1 = "FILE FOLDER*" fullword ascii
    $s2 = "?sOMA%#R60" fullword ascii
    $s3 = "@Clean" fullword ascii
    $s4 = "5t Visual Audio\\1C'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}