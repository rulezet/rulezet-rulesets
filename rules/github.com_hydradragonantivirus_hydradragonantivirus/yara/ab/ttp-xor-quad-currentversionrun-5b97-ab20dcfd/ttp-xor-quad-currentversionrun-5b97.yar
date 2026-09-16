rule TTP_XOR_QUAD_CurrentVersionRun_5b97 {
  strings:
    $key_5b97 = { 08 f8 [2] 2c f6 [2] 07 da [2] 29 f8 [2] 3d e3 [2] 32 f9 [2] 2c e4 [2] 2e e5 [2] 35 e3 [2] 29 e4 [2] 35 cb }

  condition:
    any of them
}