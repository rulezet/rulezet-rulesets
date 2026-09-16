rule TTP_XOR_QUAD_CurrentVersionRun_618e {
  strings:
    $key_618e = { 32 e1 [2] 16 ef [2] 3d c3 [2] 13 e1 [2] 07 fa [2] 08 e0 [2] 16 fd [2] 14 fc [2] 0f fa [2] 13 fd [2] 0f d2 }

  condition:
    any of them
}