rule TTP_XOR_QUAD_CurrentVersionRun_9fd0 {
  strings:
    $key_9fd0 = { cc bf [2] e8 b1 [2] c3 9d [2] ed bf [2] f9 a4 [2] f6 be [2] e8 a3 [2] ea a2 [2] f1 a4 [2] ed a3 [2] f1 8c }

  condition:
    any of them
}