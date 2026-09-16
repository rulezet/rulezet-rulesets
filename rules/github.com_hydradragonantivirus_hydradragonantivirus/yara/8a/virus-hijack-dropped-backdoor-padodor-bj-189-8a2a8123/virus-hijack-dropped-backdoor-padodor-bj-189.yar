rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_189 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_189.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7bddc6dac92a8914c545e404365c2ff15b54bce6958c16d16968e70918be47b9"

  strings:
    $s1 = "?;Labor, a person is defined as an employee or con" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}