rule TTP_XOR_QUAD_CurrentVersionRun_9f5d {
  strings:
    $key_9f5d = { cc 32 [2] e8 3c [2] c3 10 [2] ed 32 [2] f9 29 [2] f6 33 [2] e8 2e [2] ea 2f [2] f1 29 [2] ed 2e [2] f1 01 }

  condition:
    any of them
}