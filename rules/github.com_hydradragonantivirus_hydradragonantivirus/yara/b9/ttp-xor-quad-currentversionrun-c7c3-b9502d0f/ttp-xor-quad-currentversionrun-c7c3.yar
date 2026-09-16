rule TTP_XOR_QUAD_CurrentVersionRun_c7c3 {
  strings:
    $key_c7c3 = { 94 ac [2] b0 a2 [2] 9b 8e [2] b5 ac [2] a1 b7 [2] ae ad [2] b0 b0 [2] b2 b1 [2] a9 b7 [2] b5 b0 [2] a9 9f }

  condition:
    any of them
}