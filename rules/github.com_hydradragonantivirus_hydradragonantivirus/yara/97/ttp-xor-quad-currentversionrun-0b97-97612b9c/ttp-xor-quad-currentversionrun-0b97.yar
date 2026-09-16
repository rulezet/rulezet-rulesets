rule TTP_XOR_QUAD_CurrentVersionRun_0b97 {
  strings:
    $key_0b97 = { 58 f8 [2] 7c f6 [2] 57 da [2] 79 f8 [2] 6d e3 [2] 62 f9 [2] 7c e4 [2] 7e e5 [2] 65 e3 [2] 79 e4 [2] 65 cb }

  condition:
    any of them
}