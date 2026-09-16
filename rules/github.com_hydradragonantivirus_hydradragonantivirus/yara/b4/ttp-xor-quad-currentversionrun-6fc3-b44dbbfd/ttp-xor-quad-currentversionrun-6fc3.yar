rule TTP_XOR_QUAD_CurrentVersionRun_6fc3 {
  strings:
    $key_6fc3 = { 3c ac [2] 18 a2 [2] 33 8e [2] 1d ac [2] 09 b7 [2] 06 ad [2] 18 b0 [2] 1a b1 [2] 01 b7 [2] 1d b0 [2] 01 9f }

  condition:
    any of them
}