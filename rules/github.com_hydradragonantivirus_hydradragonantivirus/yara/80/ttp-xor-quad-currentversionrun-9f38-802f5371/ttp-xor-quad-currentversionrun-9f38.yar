rule TTP_XOR_QUAD_CurrentVersionRun_9f38 {
  strings:
    $key_9f38 = { cc 57 [2] e8 59 [2] c3 75 [2] ed 57 [2] f9 4c [2] f6 56 [2] e8 4b [2] ea 4a [2] f1 4c [2] ed 4b [2] f1 64 }

  condition:
    any of them
}