rule TTP_XOR_QUAD_CurrentVersionRun_6fb4 {
  strings:
    $key_6fb4 = { 3c db [2] 18 d5 [2] 33 f9 [2] 1d db [2] 09 c0 [2] 06 da [2] 18 c7 [2] 1a c6 [2] 01 c0 [2] 1d c7 [2] 01 e8 }

  condition:
    any of them
}