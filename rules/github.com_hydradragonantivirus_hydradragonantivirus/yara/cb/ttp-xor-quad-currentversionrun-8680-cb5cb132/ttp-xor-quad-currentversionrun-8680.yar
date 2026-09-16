rule TTP_XOR_QUAD_CurrentVersionRun_8680 {
  strings:
    $key_8680 = { d5 ef [2] f1 e1 [2] da cd [2] f4 ef [2] e0 f4 [2] ef ee [2] f1 f3 [2] f3 f2 [2] e8 f4 [2] f4 f3 [2] e8 dc }

  condition:
    any of them
}