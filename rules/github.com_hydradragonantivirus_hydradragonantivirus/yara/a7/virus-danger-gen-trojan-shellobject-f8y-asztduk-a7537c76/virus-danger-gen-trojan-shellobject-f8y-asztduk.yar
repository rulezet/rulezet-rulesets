rule Virus_Danger_Gen_Trojan_ShellObject_f8Y_aSZtDuk {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.f8Y@aSZtDuk.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f02f3f00147d020777ca6d6b75f674a5c57b39492a232a7538c5096fdf31b80"

  strings:
    $s1 = "L)or service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}