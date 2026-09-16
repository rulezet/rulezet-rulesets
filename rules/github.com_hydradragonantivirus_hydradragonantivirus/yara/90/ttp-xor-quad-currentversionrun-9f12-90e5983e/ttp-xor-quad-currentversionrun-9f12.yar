rule TTP_XOR_QUAD_CurrentVersionRun_9f12 {
  strings:
    $key_9f12 = { cc 7d [2] e8 73 [2] c3 5f [2] ed 7d [2] f9 66 [2] f6 7c [2] e8 61 [2] ea 60 [2] f1 66 [2] ed 61 [2] f1 4e }

  condition:
    any of them
}