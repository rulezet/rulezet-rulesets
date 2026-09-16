rule TTP_XOR_QUAD_CurrentVersionRun_c3c3 {
  strings:
    $key_c3c3 = { 90 ac [2] b4 a2 [2] 9f 8e [2] b1 ac [2] a5 b7 [2] aa ad [2] b4 b0 [2] b6 b1 [2] ad b7 [2] b1 b0 [2] ad 9f }

  condition:
    any of them
}