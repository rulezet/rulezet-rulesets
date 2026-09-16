rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aSZtDuk_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aSZtDuk_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54947243ae17c52208096ebfcc5c844654adba7c0d9778fa6d4772d6c79ede11"

  strings:
    $s1 = "/^or service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}