rule TTP_XOR_QUAD_CurrentVersionRun_9fca {
  strings:
    $key_9fca = { cc a5 [2] e8 ab [2] c3 87 [2] ed a5 [2] f9 be [2] f6 a4 [2] e8 b9 [2] ea b8 [2] f1 be [2] ed b9 [2] f1 96 }

  condition:
    any of them
}