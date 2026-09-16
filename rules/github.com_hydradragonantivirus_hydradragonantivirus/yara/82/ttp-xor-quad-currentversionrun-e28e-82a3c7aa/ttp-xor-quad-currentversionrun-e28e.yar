rule TTP_XOR_QUAD_CurrentVersionRun_e28e {
  strings:
    $key_e28e = { b1 e1 [2] 95 ef [2] be c3 [2] 90 e1 [2] 84 fa [2] 8b e0 [2] 95 fd [2] 97 fc [2] 8c fa [2] 90 fd [2] 8c d2 }

  condition:
    any of them
}