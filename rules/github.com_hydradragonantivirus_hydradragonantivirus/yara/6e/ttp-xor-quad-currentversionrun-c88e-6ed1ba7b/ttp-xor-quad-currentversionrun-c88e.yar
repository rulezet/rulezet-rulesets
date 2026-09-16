rule TTP_XOR_QUAD_CurrentVersionRun_c88e {
  strings:
    $key_c88e = { 9b e1 [2] bf ef [2] 94 c3 [2] ba e1 [2] ae fa [2] a1 e0 [2] bf fd [2] bd fc [2] a6 fa [2] ba fd [2] a6 d2 }

  condition:
    any of them
}