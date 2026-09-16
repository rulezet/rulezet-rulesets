rule TTP_XOR_QUAD_CurrentVersionRun_4d8e {
  strings:
    $key_4d8e = { 1e e1 [2] 3a ef [2] 11 c3 [2] 3f e1 [2] 2b fa [2] 24 e0 [2] 3a fd [2] 38 fc [2] 23 fa [2] 3f fd [2] 23 d2 }

  condition:
    any of them
}