rule Virus_Hijack_Gen_Trojan_ShellObject_f8Y_aSZtDuk_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aSZtDuk_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02bcb2cad62ff8f931bc48e22f2224aa896826faebe7a2b1600479a5fff409c6"

  strings:
    $s1 = "1or service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}