rule TTP_XOR_QUAD_CurrentVersionRun_f68e {
  strings:
    $key_f68e = { a5 e1 [2] 81 ef [2] aa c3 [2] 84 e1 [2] 90 fa [2] 9f e0 [2] 81 fd [2] 83 fc [2] 98 fa [2] 84 fd [2] 98 d2 }

  condition:
    any of them
}