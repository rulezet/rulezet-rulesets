rule Virus_Hijack_Gen_Trojan_ShellObject_lyZ_aSgChKg_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.lyZ@aSgChKg_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2c2226ca9ee1f1594f216102f05c6687bde50ed4f7102a4679c8f855b3aef6e"

  strings:
    $s1 = "Copyright (C) syphilologist 2018" fullword wide
    $s2 = "universalia" fullword wide
    $s3 = "fZHIkIp {T3r@Y-1ke3:IPhT](chIT@|dvVm{@1b%4h5L;r(>Do<1T[Z-pOwu7%-f>qMNp{f>lAE[4+--zZ#H}x0zynl+5zy}Ce~E$Ein`P}~3OHcSA+c]]Vqy]%[nae" ascii
    $s4 = "fZHIkIp {T3r@Y-1ke3:IPhT](chIT@|dvVm{@1b%4h5L;r(>Do<1T[Z-pOwu7%-f>qMNp{f>lAE[4+--zZ#H}x0zynl+5zy}Ce~E$Ein`P}~3OHcSA+c]]Vqy]%[nae" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}