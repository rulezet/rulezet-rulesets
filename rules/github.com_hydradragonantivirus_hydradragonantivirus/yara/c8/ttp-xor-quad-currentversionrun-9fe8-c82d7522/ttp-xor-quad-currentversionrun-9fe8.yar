rule TTP_XOR_QUAD_CurrentVersionRun_9fe8 {
  strings:
    $key_9fe8 = { cc 87 [2] e8 89 [2] c3 a5 [2] ed 87 [2] f9 9c [2] f6 86 [2] e8 9b [2] ea 9a [2] f1 9c [2] ed 9b [2] f1 b4 }

  condition:
    any of them
}