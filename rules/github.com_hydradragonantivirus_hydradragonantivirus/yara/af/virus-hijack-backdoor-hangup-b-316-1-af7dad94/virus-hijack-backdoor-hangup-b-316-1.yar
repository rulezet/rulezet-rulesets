rule Virus_Hijack_Backdoor_Hangup_B_316_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_316_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d11af9bdc450ee3cebc51166c4a890eb1599d1c8ad381e068c63490658500684"

  strings:
    $s1 = "disclosure. Also, we each agree to disclose confidential information only to those employees or agents" fullword ascii
    $s2 = "r terms come with them." fullword ascii
    $s3 = "4$RUNe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}