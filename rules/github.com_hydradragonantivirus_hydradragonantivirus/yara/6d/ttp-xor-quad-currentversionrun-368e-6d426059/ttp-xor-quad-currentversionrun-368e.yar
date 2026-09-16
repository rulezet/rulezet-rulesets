rule TTP_XOR_QUAD_CurrentVersionRun_368e {
  strings:
    $key_368e = { 65 e1 [2] 41 ef [2] 6a c3 [2] 44 e1 [2] 50 fa [2] 5f e0 [2] 41 fd [2] 43 fc [2] 58 fa [2] 44 fd [2] 58 d2 }

  condition:
    any of them
}