rule TTP_XOR_QUAD_CurrentVersionRun_9f7c {
  strings:
    $key_9f7c = { cc 13 [2] e8 1d [2] c3 31 [2] ed 13 [2] f9 08 [2] f6 12 [2] e8 0f [2] ea 0e [2] f1 08 [2] ed 0f [2] f1 20 }

  condition:
    any of them
}