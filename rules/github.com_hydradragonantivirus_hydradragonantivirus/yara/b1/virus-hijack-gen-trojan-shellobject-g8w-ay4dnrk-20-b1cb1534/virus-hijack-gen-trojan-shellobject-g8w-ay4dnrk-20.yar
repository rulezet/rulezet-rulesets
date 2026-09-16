rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ay4DNrk_20 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ay4DNrk_20.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a640b59248e737a2635b26cb6d9f8c61d7f26c3eca5f21bde4d7d702f5f07fb2"

  strings:
    $s1 = "1America, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}