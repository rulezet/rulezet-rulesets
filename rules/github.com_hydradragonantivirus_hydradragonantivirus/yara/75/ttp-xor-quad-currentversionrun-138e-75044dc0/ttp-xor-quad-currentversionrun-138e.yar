rule TTP_XOR_QUAD_CurrentVersionRun_138e {
  strings:
    $key_138e = { 40 e1 [2] 64 ef [2] 4f c3 [2] 61 e1 [2] 75 fa [2] 7a e0 [2] 64 fd [2] 66 fc [2] 7d fa [2] 61 fd [2] 7d d2 }

  condition:
    any of them
}