rule TTP_XOR_QUAD_CurrentVersionRun_1b97 {
  strings:
    $key_1b97 = { 48 f8 [2] 6c f6 [2] 47 da [2] 69 f8 [2] 7d e3 [2] 72 f9 [2] 6c e4 [2] 6e e5 [2] 75 e3 [2] 69 e4 [2] 75 cb }

  condition:
    any of them
}