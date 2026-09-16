rule TTP_XOR_QUAD_CurrentVersionRun_3497 {
  strings:
    $key_3497 = { 67 f8 [2] 43 f6 [2] 68 da [2] 46 f8 [2] 52 e3 [2] 5d f9 [2] 43 e4 [2] 41 e5 [2] 5a e3 [2] 46 e4 [2] 5a cb }

  condition:
    any of them
}