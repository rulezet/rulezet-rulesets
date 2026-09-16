rule TTP_XOR_QUAD_CurrentVersionRun_9f01 {
  strings:
    $key_9f01 = { cc 6e [2] e8 60 [2] c3 4c [2] ed 6e [2] f9 75 [2] f6 6f [2] e8 72 [2] ea 73 [2] f1 75 [2] ed 72 [2] f1 5d }

  condition:
    any of them
}