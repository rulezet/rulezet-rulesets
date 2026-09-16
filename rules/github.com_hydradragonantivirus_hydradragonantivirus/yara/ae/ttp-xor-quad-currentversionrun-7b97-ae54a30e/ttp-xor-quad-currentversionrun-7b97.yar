rule TTP_XOR_QUAD_CurrentVersionRun_7b97 {
  strings:
    $key_7b97 = { 28 f8 [2] 0c f6 [2] 27 da [2] 09 f8 [2] 1d e3 [2] 12 f9 [2] 0c e4 [2] 0e e5 [2] 15 e3 [2] 09 e4 [2] 15 cb }

  condition:
    any of them
}