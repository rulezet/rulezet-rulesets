rule TTP_XOR_QUAD_CurrentVersionRun_8a83 {
  strings:
    $key_8a83 = { d9 ec [2] fd e2 [2] d6 ce [2] f8 ec [2] ec f7 [2] e3 ed [2] fd f0 [2] ff f1 [2] e4 f7 [2] f8 f0 [2] e4 df }

  condition:
    any of them
}