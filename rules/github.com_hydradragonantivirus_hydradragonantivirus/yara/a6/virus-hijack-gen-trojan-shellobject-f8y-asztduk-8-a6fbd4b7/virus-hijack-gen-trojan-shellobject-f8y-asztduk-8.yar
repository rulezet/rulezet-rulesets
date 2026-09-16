rule Virus_Hijack_Gen_Trojan_ShellObject_f8Y_aSZtDuk_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aSZtDuk_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e81259c8a0b2792ef9bb5f57d441d0632ecc86502c9fce266386bb8255545fab"

  strings:
    $s1 = "Qor service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}