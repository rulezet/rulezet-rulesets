rule TTP_XOR_QUAD_CurrentVersionRun_5b8e {
  strings:
    $key_5b8e = { 08 e1 [2] 2c ef [2] 07 c3 [2] 29 e1 [2] 3d fa [2] 32 e0 [2] 2c fd [2] 2e fc [2] 35 fa [2] 29 fd [2] 35 d2 }

  condition:
    any of them
}