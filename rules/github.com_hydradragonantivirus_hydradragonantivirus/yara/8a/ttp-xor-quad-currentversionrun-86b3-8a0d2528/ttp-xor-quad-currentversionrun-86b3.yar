rule TTP_XOR_QUAD_CurrentVersionRun_86b3 {
  strings:
    $key_86b3 = { d5 dc [2] f1 d2 [2] da fe [2] f4 dc [2] e0 c7 [2] ef dd [2] f1 c0 [2] f3 c1 [2] e8 c7 [2] f4 c0 [2] e8 ef }

  condition:
    any of them
}