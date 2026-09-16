rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aCMzZah_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aCMzZah_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29073ae232f5327f0048b0c14cabeda7378d5e786ab64c2cbbe0c9a80b29afb3"

  strings:
    $s1 = "SItH(\"" fullword ascii
    $s2 = "WOrT(&" fullword ascii
    $s3 = "PLUg}&" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}