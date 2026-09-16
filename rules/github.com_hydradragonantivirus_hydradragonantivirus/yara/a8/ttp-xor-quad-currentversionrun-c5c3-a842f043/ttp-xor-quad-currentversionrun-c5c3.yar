rule TTP_XOR_QUAD_CurrentVersionRun_c5c3 {
  strings:
    $key_c5c3 = { 96 ac [2] b2 a2 [2] 99 8e [2] b7 ac [2] a3 b7 [2] ac ad [2] b2 b0 [2] b0 b1 [2] ab b7 [2] b7 b0 [2] ab 9f }

  condition:
    any of them
}