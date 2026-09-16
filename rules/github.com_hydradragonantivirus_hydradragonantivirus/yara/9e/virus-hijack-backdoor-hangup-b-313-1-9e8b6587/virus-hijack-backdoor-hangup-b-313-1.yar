rule Virus_Hijack_Backdoor_Hangup_B_313_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_313_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad8a76d100b4c81e014f788eb04e117d760205a913c5b099eb5e061e05069a8a"

  strings:
    $s1 = "disclosure. Also, we each agree to disclose confidential information only to those employees or agents" fullword ascii
    $s2 = "r terms come with them." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}