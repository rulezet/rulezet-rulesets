rule TTP_XOR_QUAD_CurrentVersionRun_8372 {
  strings:
    $key_8372 = { d0 1d [2] f4 13 [2] df 3f [2] f1 1d [2] e5 06 [2] ea 1c [2] f4 01 [2] f6 00 [2] ed 06 [2] f1 01 [2] ed 2e }

  condition:
    any of them
}