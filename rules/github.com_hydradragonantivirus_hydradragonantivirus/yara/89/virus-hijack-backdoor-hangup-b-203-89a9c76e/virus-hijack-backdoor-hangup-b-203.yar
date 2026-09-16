rule Virus_Hijack_Backdoor_Hangup_B_203 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_203.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e2cfdd7455fd1f0864f15dc0227e19a1fcdd68088a91fc412c70322b3229037"

  strings:
    $s1 = "&your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}