rule TTP_XOR_QUAD_CurrentVersionRun_568e {
  strings:
    $key_568e = { 05 e1 [2] 21 ef [2] 0a c3 [2] 24 e1 [2] 30 fa [2] 3f e0 [2] 21 fd [2] 23 fc [2] 38 fa [2] 24 fd [2] 38 d2 }

  condition:
    any of them
}