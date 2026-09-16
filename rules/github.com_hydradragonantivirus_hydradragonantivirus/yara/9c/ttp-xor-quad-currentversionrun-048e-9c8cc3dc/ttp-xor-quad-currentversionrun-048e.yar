rule TTP_XOR_QUAD_CurrentVersionRun_048e {
  strings:
    $key_048e = { 57 e1 [2] 73 ef [2] 58 c3 [2] 76 e1 [2] 62 fa [2] 6d e0 [2] 73 fd [2] 71 fc [2] 6a fa [2] 76 fd [2] 6a d2 }

  condition:
    any of them
}