rule TTP_XOR_QUAD_CurrentVersionRun_e497 {
  strings:
    $key_e497 = { b7 f8 [2] 93 f6 [2] b8 da [2] 96 f8 [2] 82 e3 [2] 8d f9 [2] 93 e4 [2] 91 e5 [2] 8a e3 [2] 96 e4 [2] 8a cb }

  condition:
    any of them
}