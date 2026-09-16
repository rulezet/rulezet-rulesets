rule Virus_Hijack_Backdoor_Hangup_B_311_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_311_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44246de85c7aafa77166701b216b647807c4f01ad5917534dff4258b6b6a64e9"

  strings:
    $s1 = "disclosure. Also, we each agree to disclose confidential information only to those employees or agents" fullword ascii
    $s2 = "r terms come with them." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}