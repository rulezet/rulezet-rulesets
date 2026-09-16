rule TTP_XOR_QUAD_CurrentVersionRun_2297 {
  strings:
    $key_2297 = { 71 f8 [2] 55 f6 [2] 7e da [2] 50 f8 [2] 44 e3 [2] 4b f9 [2] 55 e4 [2] 57 e5 [2] 4c e3 [2] 50 e4 [2] 4c cb }

  condition:
    any of them
}