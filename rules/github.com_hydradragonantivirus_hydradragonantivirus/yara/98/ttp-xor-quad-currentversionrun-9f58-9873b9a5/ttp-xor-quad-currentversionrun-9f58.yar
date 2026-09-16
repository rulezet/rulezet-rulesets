rule TTP_XOR_QUAD_CurrentVersionRun_9f58 {
  strings:
    $key_9f58 = { cc 37 [2] e8 39 [2] c3 15 [2] ed 37 [2] f9 2c [2] f6 36 [2] e8 2b [2] ea 2a [2] f1 2c [2] ed 2b [2] f1 04 }

  condition:
    any of them
}