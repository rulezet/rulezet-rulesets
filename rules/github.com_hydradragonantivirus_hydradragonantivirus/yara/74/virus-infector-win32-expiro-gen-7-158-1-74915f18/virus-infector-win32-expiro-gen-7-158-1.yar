rule Virus_Infector_Win32_Expiro_Gen_7_158_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_158_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f06cbfd8e2fb34d691ab0e75fa0ff1c8f2f42e0de887ddaeccc69331a81bb2a"

  strings:
    $s1 = ",Reference Viewing Condition in IE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}