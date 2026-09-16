rule TTP_XOR_QUAD_CurrentVersionRun_2a8e {
  strings:
    $key_2a8e = { 79 e1 [2] 5d ef [2] 76 c3 [2] 58 e1 [2] 4c fa [2] 43 e0 [2] 5d fd [2] 5f fc [2] 44 fa [2] 58 fd [2] 44 d2 }

  condition:
    any of them
}