rule TTP_XOR_QUAD_CurrentVersionRun_9fa8 {
  strings:
    $key_9fa8 = { cc c7 [2] e8 c9 [2] c3 e5 [2] ed c7 [2] f9 dc [2] f6 c6 [2] e8 db [2] ea da [2] f1 dc [2] ed db [2] f1 f4 }

  condition:
    any of them
}