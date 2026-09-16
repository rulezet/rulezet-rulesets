rule Trojan_Hooker_Win32_Floxif_A_55 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_55.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc7151003037e66d9948b4ec5fb45975fadc4e5906bdba606904e721ffa654b6"

  strings:
    $s1 = "Bits index out of range/Menu '%s' is already being used by another form*Windows socket error: %s (%d), on API '%s'" fullword wide
    $s2 = "<description>WindowsVistaReadiness Application</description>" fullword ascii
    $s3 = "Can't create new socket)Can't change value while socket is active" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}