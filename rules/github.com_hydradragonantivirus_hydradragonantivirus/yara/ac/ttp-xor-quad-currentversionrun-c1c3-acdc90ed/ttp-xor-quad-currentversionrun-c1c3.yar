rule TTP_XOR_QUAD_CurrentVersionRun_c1c3 {
  strings:
    $key_c1c3 = { 92 ac [2] b6 a2 [2] 9d 8e [2] b3 ac [2] a7 b7 [2] a8 ad [2] b6 b0 [2] b4 b1 [2] af b7 [2] b3 b0 [2] af 9f }

  condition:
    any of them
}