rule TTP_XOR_QUAD_CurrentVersionRun_8347 {
  strings:
    $key_8347 = { d0 28 [2] f4 26 [2] df 0a [2] f1 28 [2] e5 33 [2] ea 29 [2] f4 34 [2] f6 35 [2] ed 33 [2] f1 34 [2] ed 1b }

  condition:
    any of them
}