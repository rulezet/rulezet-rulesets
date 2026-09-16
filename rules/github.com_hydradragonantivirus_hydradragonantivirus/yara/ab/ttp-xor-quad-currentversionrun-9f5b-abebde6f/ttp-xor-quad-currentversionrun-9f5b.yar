rule TTP_XOR_QUAD_CurrentVersionRun_9f5b {
  strings:
    $key_9f5b = { cc 34 [2] e8 3a [2] c3 16 [2] ed 34 [2] f9 2f [2] f6 35 [2] e8 28 [2] ea 29 [2] f1 2f [2] ed 28 [2] f1 07 }

  condition:
    any of them
}