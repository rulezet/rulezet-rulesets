rule TTP_XOR_QUAD_CurrentVersionRun_9fc9 {
  strings:
    $key_9fc9 = { cc a6 [2] e8 a8 [2] c3 84 [2] ed a6 [2] f9 bd [2] f6 a7 [2] e8 ba [2] ea bb [2] f1 bd [2] ed ba [2] f1 95 }

  condition:
    any of them
}