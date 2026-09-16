rule Trojan_Autorun_Win32_Virlock_Gen_1_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Win32.Virlock.Gen.1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a858f221a44a8456754734373a765ee9e52f08b4ec04590b9140eb898656fee5"

  strings:
    $s1 = "#that party must agree that this agreement applies to the transfer and use of the software. You may not" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}