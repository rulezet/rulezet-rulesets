rule TTP_XOR_QUAD_CurrentVersionRun_528e {
  strings:
    $key_528e = { 01 e1 [2] 25 ef [2] 0e c3 [2] 20 e1 [2] 34 fa [2] 3b e0 [2] 25 fd [2] 27 fc [2] 3c fa [2] 20 fd [2] 3c d2 }

  condition:
    any of them
}