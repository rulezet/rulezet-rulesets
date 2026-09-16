rule _Virus_Hijack_Dropped_Backdoor_Padodor_BJ_251_1_Virus_Hijack_Gen_504 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Dropped.Backdoor.Padodor.BJ_251_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.puZ@aKo42Jj_3_2.vir, Virus.Hijack_Trojan.GenericKDZ.105924_217_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6e55daccf192d4f3c27c67b0b6a2eeafa7febe554d9d07d042cbe0384d4374c"
    hash2       = "e017175bbb5b8bf16f81791bbf9e401d9c4a0fa91df6f2b0e2a8efb20546fd75"
    hash3       = "c8b0f9bf95d6db6d8c8b7aed0877289dc9685d80ba3c158cceedb0768db4e4bd"

  strings:
    $s1 = "Error obtaining wow64 process status" fullword ascii
    $s2 = "Invalid processor architecture" fullword ascii
    $s3 = "Usage: %S <option..>" fullword ascii
    $s4 = "Error opening filepath" fullword ascii
    $s5 = "  -f --file         <path>" fullword ascii
    $s6 = "Invalid DOS file" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}