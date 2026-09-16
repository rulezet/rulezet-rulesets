rule TTP_XOR_QUAD_CurrentVersionRun_3b8e {
  strings:
    $key_3b8e = { 68 e1 [2] 4c ef [2] 67 c3 [2] 49 e1 [2] 5d fa [2] 52 e0 [2] 4c fd [2] 4e fc [2] 55 fa [2] 49 fd [2] 55 d2 }

  condition:
    any of them
}