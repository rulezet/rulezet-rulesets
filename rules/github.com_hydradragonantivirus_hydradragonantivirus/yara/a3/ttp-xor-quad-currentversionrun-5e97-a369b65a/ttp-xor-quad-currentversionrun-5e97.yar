rule TTP_XOR_QUAD_CurrentVersionRun_5e97 {
  strings:
    $key_5e97 = { 0d f8 [2] 29 f6 [2] 02 da [2] 2c f8 [2] 38 e3 [2] 37 f9 [2] 29 e4 [2] 2b e5 [2] 30 e3 [2] 2c e4 [2] 30 cb }

  condition:
    any of them
}