rule TTP_XOR_QUAD_CurrentVersionRun_078e {
  strings:
    $key_078e = { 54 e1 [2] 70 ef [2] 5b c3 [2] 75 e1 [2] 61 fa [2] 6e e0 [2] 70 fd [2] 72 fc [2] 69 fa [2] 75 fd [2] 69 d2 }

  condition:
    any of them
}