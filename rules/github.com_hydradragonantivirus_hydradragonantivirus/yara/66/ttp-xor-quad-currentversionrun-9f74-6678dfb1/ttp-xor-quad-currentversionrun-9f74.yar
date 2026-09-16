rule TTP_XOR_QUAD_CurrentVersionRun_9f74 {
  strings:
    $key_9f74 = { cc 1b [2] e8 15 [2] c3 39 [2] ed 1b [2] f9 00 [2] f6 1a [2] e8 07 [2] ea 06 [2] f1 00 [2] ed 07 [2] f1 28 }

  condition:
    any of them
}