rule TTP_XOR_QUAD_CurrentVersionRun_9f9b {
  strings:
    $key_9f9b = { cc f4 [2] e8 fa [2] c3 d6 [2] ed f4 [2] f9 ef [2] f6 f5 [2] e8 e8 [2] ea e9 [2] f1 ef [2] ed e8 [2] f1 c7 }

  condition:
    any of them
}