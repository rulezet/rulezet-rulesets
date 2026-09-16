rule TTP_XOR_QUAD_CurrentVersionRun_f58e {
  strings:
    $key_f58e = { a6 e1 [2] 82 ef [2] a9 c3 [2] 87 e1 [2] 93 fa [2] 9c e0 [2] 82 fd [2] 80 fc [2] 9b fa [2] 87 fd [2] 9b d2 }

  condition:
    any of them
}