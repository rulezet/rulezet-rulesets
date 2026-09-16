rule TTP_XOR_QUAD_CurrentVersionRun_4b97 {
  strings:
    $key_4b97 = { 18 f8 [2] 3c f6 [2] 17 da [2] 39 f8 [2] 2d e3 [2] 22 f9 [2] 3c e4 [2] 3e e5 [2] 25 e3 [2] 39 e4 [2] 25 cb }

  condition:
    any of them
}