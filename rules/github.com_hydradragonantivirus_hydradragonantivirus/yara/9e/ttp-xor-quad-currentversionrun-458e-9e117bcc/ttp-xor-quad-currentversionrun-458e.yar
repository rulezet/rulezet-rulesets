rule TTP_XOR_QUAD_CurrentVersionRun_458e {
  strings:
    $key_458e = { 16 e1 [2] 32 ef [2] 19 c3 [2] 37 e1 [2] 23 fa [2] 2c e0 [2] 32 fd [2] 30 fc [2] 2b fa [2] 37 fd [2] 2b d2 }

  condition:
    any of them
}