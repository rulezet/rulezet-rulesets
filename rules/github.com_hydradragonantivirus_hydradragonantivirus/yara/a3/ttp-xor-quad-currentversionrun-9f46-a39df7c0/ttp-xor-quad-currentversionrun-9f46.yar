rule TTP_XOR_QUAD_CurrentVersionRun_9f46 {
  strings:
    $key_9f46 = { cc 29 [2] e8 27 [2] c3 0b [2] ed 29 [2] f9 32 [2] f6 28 [2] e8 35 [2] ea 34 [2] f1 32 [2] ed 35 [2] f1 1a }

  condition:
    any of them
}