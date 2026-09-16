rule TTP_XOR_QUAD_CurrentVersionRun_9f72 {
  strings:
    $key_9f72 = { cc 1d [2] e8 13 [2] c3 3f [2] ed 1d [2] f9 06 [2] f6 1c [2] e8 01 [2] ea 00 [2] f1 06 [2] ed 01 [2] f1 2e }

  condition:
    any of them
}