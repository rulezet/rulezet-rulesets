rule TTP_XOR_QUAD_CurrentVersionRun_edc3 {
  strings:
    $key_edc3 = { be ac [2] 9a a2 [2] b1 8e [2] 9f ac [2] 8b b7 [2] 84 ad [2] 9a b0 [2] 98 b1 [2] 83 b7 [2] 9f b0 [2] 83 9f }

  condition:
    any of them
}