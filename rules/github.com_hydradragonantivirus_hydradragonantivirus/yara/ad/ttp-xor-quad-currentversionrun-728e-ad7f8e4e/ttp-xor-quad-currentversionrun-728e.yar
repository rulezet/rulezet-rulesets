rule TTP_XOR_QUAD_CurrentVersionRun_728e {
  strings:
    $key_728e = { 21 e1 [2] 05 ef [2] 2e c3 [2] 00 e1 [2] 14 fa [2] 1b e0 [2] 05 fd [2] 07 fc [2] 1c fa [2] 00 fd [2] 1c d2 }

  condition:
    any of them
}