rule TTP_XOR_QUAD_CurrentVersionRun_c6df {
  strings:
    $key_c6df = { 95 b0 [2] b1 be [2] 9a 92 [2] b4 b0 [2] a0 ab [2] af b1 [2] b1 ac [2] b3 ad [2] a8 ab [2] b4 ac [2] a8 83 }

  condition:
    any of them
}