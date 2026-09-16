rule TTP_XOR_QUAD_CurrentVersionRun_228e {
  strings:
    $key_228e = { 71 e1 [2] 55 ef [2] 7e c3 [2] 50 e1 [2] 44 fa [2] 4b e0 [2] 55 fd [2] 57 fc [2] 4c fa [2] 50 fd [2] 4c d2 }

  condition:
    any of them
}