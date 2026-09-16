rule TTP_XOR_QUAD_CurrentVersionRun_128e {
  strings:
    $key_128e = { 41 e1 [2] 65 ef [2] 4e c3 [2] 60 e1 [2] 74 fa [2] 7b e0 [2] 65 fd [2] 67 fc [2] 7c fa [2] 60 fd [2] 7c d2 }

  condition:
    any of them
}