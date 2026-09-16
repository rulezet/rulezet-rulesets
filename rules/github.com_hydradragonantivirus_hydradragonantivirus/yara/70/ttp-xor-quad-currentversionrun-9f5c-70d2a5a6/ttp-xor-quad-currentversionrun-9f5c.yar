rule TTP_XOR_QUAD_CurrentVersionRun_9f5c {
  strings:
    $key_9f5c = { cc 33 [2] e8 3d [2] c3 11 [2] ed 33 [2] f9 28 [2] f6 32 [2] e8 2f [2] ea 2e [2] f1 28 [2] ed 2f [2] f1 00 }

  condition:
    any of them
}