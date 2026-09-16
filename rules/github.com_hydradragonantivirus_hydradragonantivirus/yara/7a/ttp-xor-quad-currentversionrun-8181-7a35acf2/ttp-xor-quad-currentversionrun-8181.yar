rule TTP_XOR_QUAD_CurrentVersionRun_8181 {
  strings:
    $key_8181 = { d2 ee [2] f6 e0 [2] dd cc [2] f3 ee [2] e7 f5 [2] e8 ef [2] f6 f2 [2] f4 f3 [2] ef f5 [2] f3 f2 [2] ef dd }

  condition:
    any of them
}