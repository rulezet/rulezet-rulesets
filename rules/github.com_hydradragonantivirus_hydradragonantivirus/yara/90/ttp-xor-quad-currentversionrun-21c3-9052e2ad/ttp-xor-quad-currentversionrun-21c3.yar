rule TTP_XOR_QUAD_CurrentVersionRun_21c3 {
  strings:
    $key_21c3 = { 72 ac [2] 56 a2 [2] 7d 8e [2] 53 ac [2] 47 b7 [2] 48 ad [2] 56 b0 [2] 54 b1 [2] 4f b7 [2] 53 b0 [2] 4f 9f }

  condition:
    any of them
}