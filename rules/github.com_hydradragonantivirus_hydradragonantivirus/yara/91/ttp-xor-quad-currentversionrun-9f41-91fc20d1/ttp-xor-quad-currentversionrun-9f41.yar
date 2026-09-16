rule TTP_XOR_QUAD_CurrentVersionRun_9f41 {
  strings:
    $key_9f41 = { cc 2e [2] e8 20 [2] c3 0c [2] ed 2e [2] f9 35 [2] f6 2f [2] e8 32 [2] ea 33 [2] f1 35 [2] ed 32 [2] f1 1d }

  condition:
    any of them
}