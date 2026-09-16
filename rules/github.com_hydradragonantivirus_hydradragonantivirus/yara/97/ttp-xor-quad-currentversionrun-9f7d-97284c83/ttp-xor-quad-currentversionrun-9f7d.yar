rule TTP_XOR_QUAD_CurrentVersionRun_9f7d {
  strings:
    $key_9f7d = { cc 12 [2] e8 1c [2] c3 30 [2] ed 12 [2] f9 09 [2] f6 13 [2] e8 0e [2] ea 0f [2] f1 09 [2] ed 0e [2] f1 21 }

  condition:
    any of them
}