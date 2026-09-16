rule TTP_XOR_QUAD_CurrentVersionRun_9fdf {
  strings:
    $key_9fdf = { cc b0 [2] e8 be [2] c3 92 [2] ed b0 [2] f9 ab [2] f6 b1 [2] e8 ac [2] ea ad [2] f1 ab [2] ed ac [2] f1 83 }

  condition:
    any of them
}