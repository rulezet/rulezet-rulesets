rule TTP_XOR_QUAD_CurrentVersionRun_9ffc {
  strings:
    $key_9ffc = { cc 93 [2] e8 9d [2] c3 b1 [2] ed 93 [2] f9 88 [2] f6 92 [2] e8 8f [2] ea 8e [2] f1 88 [2] ed 8f [2] f1 a0 }

  condition:
    any of them
}