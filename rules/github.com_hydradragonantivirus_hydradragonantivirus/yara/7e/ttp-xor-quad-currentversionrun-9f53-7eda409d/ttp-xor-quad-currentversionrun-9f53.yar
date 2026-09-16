rule TTP_XOR_QUAD_CurrentVersionRun_9f53 {
  strings:
    $key_9f53 = { cc 3c [2] e8 32 [2] c3 1e [2] ed 3c [2] f9 27 [2] f6 3d [2] e8 20 [2] ea 21 [2] f1 27 [2] ed 20 [2] f1 0f }

  condition:
    any of them
}