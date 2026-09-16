rule TTP_XOR_QUAD_CurrentVersionRun_9f2c {
  strings:
    $key_9f2c = { cc 43 [2] e8 4d [2] c3 61 [2] ed 43 [2] f9 58 [2] f6 42 [2] e8 5f [2] ea 5e [2] f1 58 [2] ed 5f [2] f1 70 }

  condition:
    any of them
}