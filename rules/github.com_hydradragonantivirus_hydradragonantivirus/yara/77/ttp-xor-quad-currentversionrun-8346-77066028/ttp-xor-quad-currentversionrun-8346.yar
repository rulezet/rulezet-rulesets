rule TTP_XOR_QUAD_CurrentVersionRun_8346 {
  strings:
    $key_8346 = { d0 29 [2] f4 27 [2] df 0b [2] f1 29 [2] e5 32 [2] ea 28 [2] f4 35 [2] f6 34 [2] ed 32 [2] f1 35 [2] ed 1a }

  condition:
    any of them
}