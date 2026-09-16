rule TTP_XOR_QUAD_CurrentVersionRun_9f37 {
  strings:
    $key_9f37 = { cc 58 [2] e8 56 [2] c3 7a [2] ed 58 [2] f9 43 [2] f6 59 [2] e8 44 [2] ea 45 [2] f1 43 [2] ed 44 [2] f1 6b }

  condition:
    any of them
}