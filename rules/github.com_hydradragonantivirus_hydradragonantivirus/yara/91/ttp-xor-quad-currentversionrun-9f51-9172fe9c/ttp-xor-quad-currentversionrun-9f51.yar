rule TTP_XOR_QUAD_CurrentVersionRun_9f51 {
  strings:
    $key_9f51 = { cc 3e [2] e8 30 [2] c3 1c [2] ed 3e [2] f9 25 [2] f6 3f [2] e8 22 [2] ea 23 [2] f1 25 [2] ed 22 [2] f1 0d }

  condition:
    any of them
}