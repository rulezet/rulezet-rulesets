rule TTP_XOR_QUAD_CurrentVersionRun_9f23 {
  strings:
    $key_9f23 = { cc 4c [2] e8 42 [2] c3 6e [2] ed 4c [2] f9 57 [2] f6 4d [2] e8 50 [2] ea 51 [2] f1 57 [2] ed 50 [2] f1 7f }

  condition:
    any of them
}