rule TTP_XOR_QUAD_CurrentVersionRun_0297 {
  strings:
    $key_0297 = { 51 f8 [2] 75 f6 [2] 5e da [2] 70 f8 [2] 64 e3 [2] 6b f9 [2] 75 e4 [2] 77 e5 [2] 6c e3 [2] 70 e4 [2] 6c cb }

  condition:
    any of them
}