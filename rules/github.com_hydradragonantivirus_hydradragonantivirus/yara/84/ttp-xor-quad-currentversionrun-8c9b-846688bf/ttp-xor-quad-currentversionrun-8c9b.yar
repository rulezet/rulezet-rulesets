rule TTP_XOR_QUAD_CurrentVersionRun_8c9b {
  strings:
    $key_8c9b = { df f4 [2] fb fa [2] d0 d6 [2] fe f4 [2] ea ef [2] e5 f5 [2] fb e8 [2] f9 e9 [2] e2 ef [2] fe e8 [2] e2 c7 }

  condition:
    any of them
}