rule TTP_XOR_QUAD_CurrentVersionRun_9a9b {
  strings:
    $key_9a9b = { c9 f4 [2] ed fa [2] c6 d6 [2] e8 f4 [2] fc ef [2] f3 f5 [2] ed e8 [2] ef e9 [2] f4 ef [2] e8 e8 [2] f4 c7 }

  condition:
    any of them
}