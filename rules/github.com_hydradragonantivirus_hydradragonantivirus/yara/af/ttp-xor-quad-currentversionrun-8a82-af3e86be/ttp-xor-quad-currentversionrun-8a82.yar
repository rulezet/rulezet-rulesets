rule TTP_XOR_QUAD_CurrentVersionRun_8a82 {
  strings:
    $key_8a82 = { d9 ed [2] fd e3 [2] d6 cf [2] f8 ed [2] ec f6 [2] e3 ec [2] fd f1 [2] ff f0 [2] e4 f6 [2] f8 f1 [2] e4 de }

  condition:
    any of them
}