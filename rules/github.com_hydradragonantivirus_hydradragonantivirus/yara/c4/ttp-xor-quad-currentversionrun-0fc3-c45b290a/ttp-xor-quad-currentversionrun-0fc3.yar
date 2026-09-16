rule TTP_XOR_QUAD_CurrentVersionRun_0fc3 {
  strings:
    $key_0fc3 = { 5c ac [2] 78 a2 [2] 53 8e [2] 7d ac [2] 69 b7 [2] 66 ad [2] 78 b0 [2] 7a b1 [2] 61 b7 [2] 7d b0 [2] 61 9f }

  condition:
    any of them
}