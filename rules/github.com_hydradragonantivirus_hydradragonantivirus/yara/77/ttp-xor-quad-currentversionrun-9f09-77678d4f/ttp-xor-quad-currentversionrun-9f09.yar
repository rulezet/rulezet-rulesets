rule TTP_XOR_QUAD_CurrentVersionRun_9f09 {
  strings:
    $key_9f09 = { cc 66 [2] e8 68 [2] c3 44 [2] ed 66 [2] f9 7d [2] f6 67 [2] e8 7a [2] ea 7b [2] f1 7d [2] ed 7a [2] f1 55 }

  condition:
    any of them
}