rule TTP_XOR_QUAD_CurrentVersionRun_768e {
  strings:
    $key_768e = { 25 e1 [2] 01 ef [2] 2a c3 [2] 04 e1 [2] 10 fa [2] 1f e0 [2] 01 fd [2] 03 fc [2] 18 fa [2] 04 fd [2] 18 d2 }

  condition:
    any of them
}