rule TTP_XOR_QUAD_CurrentVersionRun_6297 {
  strings:
    $key_6297 = { 31 f8 [2] 15 f6 [2] 3e da [2] 10 f8 [2] 04 e3 [2] 0b f9 [2] 15 e4 [2] 17 e5 [2] 0c e3 [2] 10 e4 [2] 0c cb }

  condition:
    any of them
}