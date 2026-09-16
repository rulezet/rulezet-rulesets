rule TTP_XOR_QUAD_CurrentVersionRun_9ff4 {
  strings:
    $key_9ff4 = { cc 9b [2] e8 95 [2] c3 b9 [2] ed 9b [2] f9 80 [2] f6 9a [2] e8 87 [2] ea 86 [2] f1 80 [2] ed 87 [2] f1 a8 }

  condition:
    any of them
}