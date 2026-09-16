rule TTP_XOR_QUAD_CurrentVersionRun_0e8e {
  strings:
    $key_0e8e = { 5d e1 [2] 79 ef [2] 52 c3 [2] 7c e1 [2] 68 fa [2] 67 e0 [2] 79 fd [2] 7b fc [2] 60 fa [2] 7c fd [2] 60 d2 }

  condition:
    any of them
}