rule TTP_XOR_QUAD_CurrentVersionRun_f08e {
  strings:
    $key_f08e = { a3 e1 [2] 87 ef [2] ac c3 [2] 82 e1 [2] 96 fa [2] 99 e0 [2] 87 fd [2] 85 fc [2] 9e fa [2] 82 fd [2] 9e d2 }

  condition:
    any of them
}