rule Virus_Hijack_Gen_Trojan_ShellObject_r0Z_a4Zmumi_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.r0Z@a4Zmumi_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f20185d030c29795018ed8626069214805b5f8d22c413a9d952880709cd1cb9"

  strings:
    $s1 = "-#giLo" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}