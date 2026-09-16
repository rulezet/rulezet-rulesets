rule TTP_XOR_QUAD_CurrentVersionRun_5497 {
  strings:
    $key_5497 = { 07 f8 [2] 23 f6 [2] 08 da [2] 26 f8 [2] 32 e3 [2] 3d f9 [2] 23 e4 [2] 21 e5 [2] 3a e3 [2] 26 e4 [2] 3a cb }

  condition:
    any of them
}