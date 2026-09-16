rule TTP_XOR_QUAD_CurrentVersionRun_9fc4 {
  strings:
    $key_9fc4 = { cc ab [2] e8 a5 [2] c3 89 [2] ed ab [2] f9 b0 [2] f6 aa [2] e8 b7 [2] ea b6 [2] f1 b0 [2] ed b7 [2] f1 98 }

  condition:
    any of them
}