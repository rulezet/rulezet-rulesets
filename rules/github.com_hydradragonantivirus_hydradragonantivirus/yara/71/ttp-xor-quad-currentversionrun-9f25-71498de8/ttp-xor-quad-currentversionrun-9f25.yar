rule TTP_XOR_QUAD_CurrentVersionRun_9f25 {
  strings:
    $key_9f25 = { cc 4a [2] e8 44 [2] c3 68 [2] ed 4a [2] f9 51 [2] f6 4b [2] e8 56 [2] ea 57 [2] f1 51 [2] ed 56 [2] f1 79 }

  condition:
    any of them
}