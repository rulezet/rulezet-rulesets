rule TTP_XOR_QUAD_CurrentVersionRun_5e8e {
  strings:
    $key_5e8e = { 0d e1 [2] 29 ef [2] 02 c3 [2] 2c e1 [2] 38 fa [2] 37 e0 [2] 29 fd [2] 2b fc [2] 30 fa [2] 2c fd [2] 30 d2 }

  condition:
    any of them
}