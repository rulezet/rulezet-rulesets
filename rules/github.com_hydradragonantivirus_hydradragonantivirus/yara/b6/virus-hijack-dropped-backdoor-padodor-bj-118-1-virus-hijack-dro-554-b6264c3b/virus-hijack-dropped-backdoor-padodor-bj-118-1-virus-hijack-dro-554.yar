rule _Virus_Hijack_Dropped_Backdoor_Padodor_BJ_118_1_Virus_Hijack_Dro_554 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Dropped.Backdoor.Padodor.BJ_118_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_251_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.puZ@aKo42Jj_3_2.vir, Virus.Hijack_Trojan.GenericKDZ.105924_202_1.vir, Virus.Hijack_Trojan.GenericKDZ.105924_217_1.vir, Virus.Hijack_Trojan.GenericKDZ.105924_219_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2ace93301adf732c37dc77a708f6a6ed9a679ee39254bb5e1eadf0cfe935e80"
    hash2       = "f6e55daccf192d4f3c27c67b0b6a2eeafa7febe554d9d07d042cbe0384d4374c"
    hash3       = "e017175bbb5b8bf16f81791bbf9e401d9c4a0fa91df6f2b0e2a8efb20546fd75"
    hash4       = "dea5aee731b62bdd9c2c9a234f6c8f21d4967d52f1194056e418e4dc03e163af"
    hash5       = "c8b0f9bf95d6db6d8c8b7aed0877289dc9685d80ba3c158cceedb0768db4e4bd"
    hash6       = "0dbe642933b76e3311ea2741dc3b509b2824480d4205e6a91425b372b85d999d"

  strings:
    $s1 = "[-] Error getting access to process: %ld!" fullword ascii
    $s2 = "[-] Error enumerating the first process: %ld" fullword ascii
    $s3 = "[-] Error finding process by name: %S" fullword ascii
    $s4 = "Error parsing commandline options!" fullword ascii
    $s5 = "[-] Error obtaining snapshot handle: %ld" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}