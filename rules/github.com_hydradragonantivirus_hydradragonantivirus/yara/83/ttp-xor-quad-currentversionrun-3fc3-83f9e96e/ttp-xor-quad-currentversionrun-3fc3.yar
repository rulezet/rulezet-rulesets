rule TTP_XOR_QUAD_CurrentVersionRun_3fc3 {
  strings:
    $key_3fc3 = { 6c ac [2] 48 a2 [2] 63 8e [2] 4d ac [2] 59 b7 [2] 56 ad [2] 48 b0 [2] 4a b1 [2] 51 b7 [2] 4d b0 [2] 51 9f }

  condition:
    any of them
}