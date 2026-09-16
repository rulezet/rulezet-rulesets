rule TTP_XOR_QUAD_CurrentVersionRun_4497 {
  strings:
    $key_4497 = { 17 f8 [2] 33 f6 [2] 18 da [2] 36 f8 [2] 22 e3 [2] 2d f9 [2] 33 e4 [2] 31 e5 [2] 2a e3 [2] 36 e4 [2] 2a cb }

  condition:
    any of them
}