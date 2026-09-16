rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_ae3yXvm_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@ae3yXvm_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7837c9f4c7504d438eb236d2378474f1d29cebaef71e86af6676671f243de83"

  strings:
    $s1 = " /c copy %s %s && dir && ipconfig" fullword wide
    $s2 = "gent from USB-flash" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}