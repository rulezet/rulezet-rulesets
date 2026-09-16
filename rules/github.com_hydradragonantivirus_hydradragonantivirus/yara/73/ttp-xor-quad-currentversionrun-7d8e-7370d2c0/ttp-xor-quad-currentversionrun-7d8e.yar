rule TTP_XOR_QUAD_CurrentVersionRun_7d8e {
  strings:
    $key_7d8e = { 2e e1 [2] 0a ef [2] 21 c3 [2] 0f e1 [2] 1b fa [2] 14 e0 [2] 0a fd [2] 08 fc [2] 13 fa [2] 0f fd [2] 13 d2 }

  condition:
    any of them
}