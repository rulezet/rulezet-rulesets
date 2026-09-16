rule TTP_XOR_QUAD_CurrentVersionRun_9fef {
  strings:
    $key_9fef = { cc 80 [2] e8 8e [2] c3 a2 [2] ed 80 [2] f9 9b [2] f6 81 [2] e8 9c [2] ea 9d [2] f1 9b [2] ed 9c [2] f1 b3 }

  condition:
    any of them
}