rule TTP_XOR_QUAD_CurrentVersionRun_9f03 {
  strings:
    $key_9f03 = { cc 6c [2] e8 62 [2] c3 4e [2] ed 6c [2] f9 77 [2] f6 6d [2] e8 70 [2] ea 71 [2] f1 77 [2] ed 70 [2] f1 5f }

  condition:
    any of them
}