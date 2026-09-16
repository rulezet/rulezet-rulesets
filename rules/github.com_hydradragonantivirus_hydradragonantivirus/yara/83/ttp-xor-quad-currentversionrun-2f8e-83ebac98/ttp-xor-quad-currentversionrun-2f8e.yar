rule TTP_XOR_QUAD_CurrentVersionRun_2f8e {
  strings:
    $key_2f8e = { 7c e1 [2] 58 ef [2] 73 c3 [2] 5d e1 [2] 49 fa [2] 46 e0 [2] 58 fd [2] 5a fc [2] 41 fa [2] 5d fd [2] 41 d2 }

  condition:
    any of them
}