rule Virus_Hijack_Gen_Trojan_ShellObject_uyZ_aWevApi_6_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.uyZ@aWevApi_6_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70629f4ca9584b0b8f2c736feb34dc4e229fa688fc7f44ee4d9e9cfd246eed2c"

  strings:
    $s1 = "Java(TM) Platform SE 6 U30" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}