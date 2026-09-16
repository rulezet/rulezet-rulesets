rule TTP_XOR_QUAD_CurrentVersionRun_4b8e {
  strings:
    $key_4b8e = { 18 e1 [2] 3c ef [2] 17 c3 [2] 39 e1 [2] 2d fa [2] 22 e0 [2] 3c fd [2] 3e fc [2] 25 fa [2] 39 fd [2] 25 d2 }

  condition:
    any of them
}