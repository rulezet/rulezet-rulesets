rule TTP_XOR_QUAD_CurrentVersionRun_9f06 {
  strings:
    $key_9f06 = { cc 69 [2] e8 67 [2] c3 4b [2] ed 69 [2] f9 72 [2] f6 68 [2] e8 75 [2] ea 74 [2] f1 72 [2] ed 75 [2] f1 5a }

  condition:
    any of them
}