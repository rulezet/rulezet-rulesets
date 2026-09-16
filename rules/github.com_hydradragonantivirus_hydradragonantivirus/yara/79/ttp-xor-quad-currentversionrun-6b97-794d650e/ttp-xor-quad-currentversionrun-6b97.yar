rule TTP_XOR_QUAD_CurrentVersionRun_6b97 {
  strings:
    $key_6b97 = { 38 f8 [2] 1c f6 [2] 37 da [2] 19 f8 [2] 0d e3 [2] 02 f9 [2] 1c e4 [2] 1e e5 [2] 05 e3 [2] 19 e4 [2] 05 cb }

  condition:
    any of them
}