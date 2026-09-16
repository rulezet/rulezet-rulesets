rule TTP_XOR_QUAD_CurrentVersionRun_5d8e {
  strings:
    $key_5d8e = { 0e e1 [2] 2a ef [2] 01 c3 [2] 2f e1 [2] 3b fa [2] 34 e0 [2] 2a fd [2] 28 fc [2] 33 fa [2] 2f fd [2] 33 d2 }

  condition:
    any of them
}