rule TTP_XOR_QUAD_CurrentVersionRun_9fc6 {
  strings:
    $key_9fc6 = { cc a9 [2] e8 a7 [2] c3 8b [2] ed a9 [2] f9 b2 [2] f6 a8 [2] e8 b5 [2] ea b4 [2] f1 b2 [2] ed b5 [2] f1 9a }

  condition:
    any of them
}