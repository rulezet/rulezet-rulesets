rule TTP_XOR_QUAD_CurrentVersionRun_5b84 {
  strings:
    $key_5b84 = { 08 eb [2] 2c e5 [2] 07 c9 [2] 29 eb [2] 3d f0 [2] 32 ea [2] 2c f7 [2] 2e f6 [2] 35 f0 [2] 29 f7 [2] 35 d8 }

  condition:
    any of them
}