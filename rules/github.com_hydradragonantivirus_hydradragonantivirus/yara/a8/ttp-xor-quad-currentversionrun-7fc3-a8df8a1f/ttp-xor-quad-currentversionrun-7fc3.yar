rule TTP_XOR_QUAD_CurrentVersionRun_7fc3 {
  strings:
    $key_7fc3 = { 2c ac [2] 08 a2 [2] 23 8e [2] 0d ac [2] 19 b7 [2] 16 ad [2] 08 b0 [2] 0a b1 [2] 11 b7 [2] 0d b0 [2] 11 9f }

  condition:
    any of them
}