rule TTP_XOR_QUAD_CurrentVersionRun_9ffa {
  strings:
    $key_9ffa = { cc 95 [2] e8 9b [2] c3 b7 [2] ed 95 [2] f9 8e [2] f6 94 [2] e8 89 [2] ea 88 [2] f1 8e [2] ed 89 [2] f1 a6 }

  condition:
    any of them
}