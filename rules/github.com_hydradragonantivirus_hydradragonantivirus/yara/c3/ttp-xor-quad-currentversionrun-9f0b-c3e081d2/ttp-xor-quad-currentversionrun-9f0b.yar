rule TTP_XOR_QUAD_CurrentVersionRun_9f0b {
  strings:
    $key_9f0b = { cc 64 [2] e8 6a [2] c3 46 [2] ed 64 [2] f9 7f [2] f6 65 [2] e8 78 [2] ea 79 [2] f1 7f [2] ed 78 [2] f1 57 }

  condition:
    any of them
}