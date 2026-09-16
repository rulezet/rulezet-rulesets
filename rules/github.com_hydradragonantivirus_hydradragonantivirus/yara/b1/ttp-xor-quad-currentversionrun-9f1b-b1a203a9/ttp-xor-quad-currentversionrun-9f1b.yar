rule TTP_XOR_QUAD_CurrentVersionRun_9f1b {
  strings:
    $key_9f1b = { cc 74 [2] e8 7a [2] c3 56 [2] ed 74 [2] f9 6f [2] f6 75 [2] e8 68 [2] ea 69 [2] f1 6f [2] ed 68 [2] f1 47 }

  condition:
    any of them
}