rule TTP_XOR_QUAD_CurrentVersionRun_708e {
  strings:
    $key_708e = { 23 e1 [2] 07 ef [2] 2c c3 [2] 02 e1 [2] 16 fa [2] 19 e0 [2] 07 fd [2] 05 fc [2] 1e fa [2] 02 fd [2] 1e d2 }

  condition:
    any of them
}