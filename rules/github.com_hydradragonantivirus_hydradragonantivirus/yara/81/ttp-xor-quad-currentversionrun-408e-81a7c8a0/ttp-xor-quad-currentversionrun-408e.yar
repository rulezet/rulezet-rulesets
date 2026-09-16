rule TTP_XOR_QUAD_CurrentVersionRun_408e {
  strings:
    $key_408e = { 13 e1 [2] 37 ef [2] 1c c3 [2] 32 e1 [2] 26 fa [2] 29 e0 [2] 37 fd [2] 35 fc [2] 2e fa [2] 32 fd [2] 2e d2 }

  condition:
    any of them
}