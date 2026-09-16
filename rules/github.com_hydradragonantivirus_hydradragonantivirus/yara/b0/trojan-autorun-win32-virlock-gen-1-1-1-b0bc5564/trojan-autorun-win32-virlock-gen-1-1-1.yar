rule Trojan_Autorun_Win32_Virlock_Gen_1_1_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Win32.Virlock.Gen.1_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f31ccc1c234a1c85bebd1acd27ae7baaac9f8f8e2355deecd7e97d9f69d8b6d8"

  strings:
    $s1 = "and you and Oracle agree to submit to the exc`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}