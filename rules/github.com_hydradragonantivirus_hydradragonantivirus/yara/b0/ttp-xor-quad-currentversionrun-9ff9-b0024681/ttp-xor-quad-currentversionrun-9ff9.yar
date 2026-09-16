rule TTP_XOR_QUAD_CurrentVersionRun_9ff9 {
  strings:
    $key_9ff9 = { cc 96 [2] e8 98 [2] c3 b4 [2] ed 96 [2] f9 8d [2] f6 97 [2] e8 8a [2] ea 8b [2] f1 8d [2] ed 8a [2] f1 a5 }

  condition:
    any of them
}