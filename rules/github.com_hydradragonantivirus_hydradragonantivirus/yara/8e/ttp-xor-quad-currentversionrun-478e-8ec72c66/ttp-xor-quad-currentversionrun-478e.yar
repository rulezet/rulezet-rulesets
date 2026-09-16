rule TTP_XOR_QUAD_CurrentVersionRun_478e {
  strings:
    $key_478e = { 14 e1 [2] 30 ef [2] 1b c3 [2] 35 e1 [2] 21 fa [2] 2e e0 [2] 30 fd [2] 32 fc [2] 29 fa [2] 35 fd [2] 29 d2 }

  condition:
    any of them
}