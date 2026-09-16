rule TTP_XOR_QUAD_CurrentVersionRun_1fc3 {
  strings:
    $key_1fc3 = { 4c ac [2] 68 a2 [2] 43 8e [2] 6d ac [2] 79 b7 [2] 76 ad [2] 68 b0 [2] 6a b1 [2] 71 b7 [2] 6d b0 [2] 71 9f }

  condition:
    any of them
}