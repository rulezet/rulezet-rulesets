rule TTP_XOR_QUAD_CurrentVersionRun_4f8e {
  strings:
    $key_4f8e = { 1c e1 [2] 38 ef [2] 13 c3 [2] 3d e1 [2] 29 fa [2] 26 e0 [2] 38 fd [2] 3a fc [2] 21 fa [2] 3d fd [2] 21 d2 }

  condition:
    any of them
}