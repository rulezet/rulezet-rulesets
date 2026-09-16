rule Virus_Hijack_Gen_Trojan_ShellObject_oSZ_aaT6Wyj_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.oSZ@aaT6Wyj_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f99ad2e0e521e7f450554e53d045e4d22d6ae9250f07765df91dc5adcbdc99ff"

  strings:
    $s1 = "~whole number for purposes of license quantity requirements." fullword ascii
    $s2 = "\\{V?:(ScyT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}