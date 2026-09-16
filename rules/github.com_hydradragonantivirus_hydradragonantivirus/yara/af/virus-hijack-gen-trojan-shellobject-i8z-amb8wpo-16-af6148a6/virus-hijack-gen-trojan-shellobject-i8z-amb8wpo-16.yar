rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_amB8wPo_16 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@amB8wPo_16.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0cc16c29f24e679ca15315871a3b8935178f8a00f579d441d9a71391a2d5778"

  strings:
    $s1 = "YOok#Jg" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}