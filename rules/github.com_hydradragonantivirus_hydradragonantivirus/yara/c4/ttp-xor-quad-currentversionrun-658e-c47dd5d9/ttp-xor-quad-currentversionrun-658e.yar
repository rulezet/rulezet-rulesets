rule TTP_XOR_QUAD_CurrentVersionRun_658e {
  strings:
    $key_658e = { 36 e1 [2] 12 ef [2] 39 c3 [2] 17 e1 [2] 03 fa [2] 0c e0 [2] 12 fd [2] 10 fc [2] 0b fa [2] 17 fd [2] 0b d2 }

  condition:
    any of them
}