rule TTP_XOR_QUAD_CurrentVersionRun_6f97 {
  strings:
    $key_6f97 = { 3c f8 [2] 18 f6 [2] 33 da [2] 1d f8 [2] 09 e3 [2] 06 f9 [2] 18 e4 [2] 1a e5 [2] 01 e3 [2] 1d e4 [2] 01 cb }

  condition:
    any of them
}