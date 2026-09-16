rule TTP_XOR_QUAD_CurrentVersionRun_9f62 {
  strings:
    $key_9f62 = { cc 0d [2] e8 03 [2] c3 2f [2] ed 0d [2] f9 16 [2] f6 0c [2] e8 11 [2] ea 10 [2] f1 16 [2] ed 11 [2] f1 3e }

  condition:
    any of them
}