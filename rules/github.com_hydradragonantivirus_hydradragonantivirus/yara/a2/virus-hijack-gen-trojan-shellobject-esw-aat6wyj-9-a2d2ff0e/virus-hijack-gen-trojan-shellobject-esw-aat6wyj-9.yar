rule Virus_Hijack_Gen_Trojan_ShellObject_eSW_aaT6Wyj_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSW@aaT6Wyj_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ce98e1f4f11f4a21a6e27c0d92e3fd763dbfd82f4b33d9fb3e2adb914cdd43a"

  strings:
    $s1 = ";whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}