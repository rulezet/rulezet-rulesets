rule Virus_Hijack_Gen_Trojan_ShellObject_z8W_aaJDqQc_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.z8W@aaJDqQc_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e3ec1b1304718de42b103a90efc4c7ef4c9441799bc006ad5c7a2e98748ac94"

  strings:
    $s1 = "|AD\\DV@\\1wqnemf/zMKHzEW[^J%jITI@CAW/uKF`SN@LE$" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}