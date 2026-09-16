rule TTP_XOR_QUAD_CurrentVersionRun_9fd5 {
  strings:
    $key_9fd5 = { cc ba [2] e8 b4 [2] c3 98 [2] ed ba [2] f9 a1 [2] f6 bb [2] e8 a6 [2] ea a7 [2] f1 a1 [2] ed a6 [2] f1 89 }

  condition:
    any of them
}