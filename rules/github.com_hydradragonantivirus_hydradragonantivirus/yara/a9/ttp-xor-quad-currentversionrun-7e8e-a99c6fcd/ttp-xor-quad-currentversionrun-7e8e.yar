rule TTP_XOR_QUAD_CurrentVersionRun_7e8e {
  strings:
    $key_7e8e = { 2d e1 [2] 09 ef [2] 22 c3 [2] 0c e1 [2] 18 fa [2] 17 e0 [2] 09 fd [2] 0b fc [2] 10 fa [2] 0c fd [2] 10 d2 }

  condition:
    any of them
}