rule TTP_XOR_QUAD_CurrentVersionRun_638e {
  strings:
    $key_638e = { 30 e1 [2] 14 ef [2] 3f c3 [2] 11 e1 [2] 05 fa [2] 0a e0 [2] 14 fd [2] 16 fc [2] 0d fa [2] 11 fd [2] 0d d2 }

  condition:
    any of them
}