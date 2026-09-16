rule Virus_Hijack_Backdoor_Hangup_B_39_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_39_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb23ec4f092af935ad9208b2f004cf76e6490715706460ee534cf7f06e46885f"

  strings:
    $s1 = "acknowledge that you will create and activate an administrator account and password and that the" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}