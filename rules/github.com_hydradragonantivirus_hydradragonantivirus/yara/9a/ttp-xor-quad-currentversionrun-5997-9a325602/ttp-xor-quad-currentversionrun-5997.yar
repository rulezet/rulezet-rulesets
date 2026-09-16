rule TTP_XOR_QUAD_CurrentVersionRun_5997 {
  strings:
    $key_5997 = { 0a f8 [2] 2e f6 [2] 05 da [2] 2b f8 [2] 3f e3 [2] 30 f9 [2] 2e e4 [2] 2c e5 [2] 37 e3 [2] 2b e4 [2] 37 cb }

  condition:
    any of them
}