rule TTP_XOR_QUAD_CurrentVersionRun_9f67 {
  strings:
    $key_9f67 = { cc 08 [2] e8 06 [2] c3 2a [2] ed 08 [2] f9 13 [2] f6 09 [2] e8 14 [2] ea 15 [2] f1 13 [2] ed 14 [2] f1 3b }

  condition:
    any of them
}