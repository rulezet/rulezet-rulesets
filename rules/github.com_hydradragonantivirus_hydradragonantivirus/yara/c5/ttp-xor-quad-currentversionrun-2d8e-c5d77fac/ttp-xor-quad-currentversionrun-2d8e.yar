rule TTP_XOR_QUAD_CurrentVersionRun_2d8e {
  strings:
    $key_2d8e = { 7e e1 [2] 5a ef [2] 71 c3 [2] 5f e1 [2] 4b fa [2] 44 e0 [2] 5a fd [2] 58 fc [2] 43 fa [2] 5f fd [2] 43 d2 }

  condition:
    any of them
}