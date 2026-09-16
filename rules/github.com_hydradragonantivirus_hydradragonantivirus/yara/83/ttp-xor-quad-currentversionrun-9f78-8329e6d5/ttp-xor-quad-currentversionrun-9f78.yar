rule TTP_XOR_QUAD_CurrentVersionRun_9f78 {
  strings:
    $key_9f78 = { cc 17 [2] e8 19 [2] c3 35 [2] ed 17 [2] f9 0c [2] f6 16 [2] e8 0b [2] ea 0a [2] f1 0c [2] ed 0b [2] f1 24 }

  condition:
    any of them
}