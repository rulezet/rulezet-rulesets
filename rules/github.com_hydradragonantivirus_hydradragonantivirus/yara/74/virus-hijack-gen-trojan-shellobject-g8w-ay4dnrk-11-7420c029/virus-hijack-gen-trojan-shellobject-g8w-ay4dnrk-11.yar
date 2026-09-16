rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ay4DNrk_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ay4DNrk_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e80649f9c4e2228f94d7d1acbc0242cb0577ff1feac2eb8f7e847197451b5e4b"

  strings:
    $s1 = "KsAmerica, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}