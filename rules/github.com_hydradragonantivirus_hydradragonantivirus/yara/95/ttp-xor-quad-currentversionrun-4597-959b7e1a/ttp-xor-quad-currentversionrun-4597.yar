rule TTP_XOR_QUAD_CurrentVersionRun_4597 {
  strings:
    $key_4597 = { 16 f8 [2] 32 f6 [2] 19 da [2] 37 f8 [2] 23 e3 [2] 2c f9 [2] 32 e4 [2] 30 e5 [2] 2b e3 [2] 37 e4 [2] 2b cb }

  condition:
    any of them
}