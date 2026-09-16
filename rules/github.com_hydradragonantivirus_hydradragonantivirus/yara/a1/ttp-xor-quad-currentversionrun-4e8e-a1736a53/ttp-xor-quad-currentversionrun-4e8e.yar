rule TTP_XOR_QUAD_CurrentVersionRun_4e8e {
  strings:
    $key_4e8e = { 1d e1 [2] 39 ef [2] 12 c3 [2] 3c e1 [2] 28 fa [2] 27 e0 [2] 39 fd [2] 3b fc [2] 20 fa [2] 3c fd [2] 20 d2 }

  condition:
    any of them
}