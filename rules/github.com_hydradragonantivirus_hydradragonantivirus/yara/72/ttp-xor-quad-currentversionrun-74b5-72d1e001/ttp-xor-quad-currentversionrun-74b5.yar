rule TTP_XOR_QUAD_CurrentVersionRun_74b5 {
  strings:
    $key_74b5 = { 27 da [2] 03 d4 [2] 28 f8 [2] 06 da [2] 12 c1 [2] 1d db [2] 03 c6 [2] 01 c7 [2] 1a c1 [2] 06 c6 [2] 1a e9 }

  condition:
    any of them
}