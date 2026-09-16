rule TTP_XOR_QUAD_CurrentVersionRun_8a84 {
  strings:
    $key_8a84 = { d9 eb [2] fd e5 [2] d6 c9 [2] f8 eb [2] ec f0 [2] e3 ea [2] fd f7 [2] ff f6 [2] e4 f0 [2] f8 f7 [2] e4 d8 }

  condition:
    any of them
}