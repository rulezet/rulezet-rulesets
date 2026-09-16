rule TTP_XOR_QUAD_CurrentVersionRun_d6df {
  strings:
    $key_d6df = { 85 b0 [2] a1 be [2] 8a 92 [2] a4 b0 [2] b0 ab [2] bf b1 [2] a1 ac [2] a3 ad [2] b8 ab [2] a4 ac [2] b8 83 }

  condition:
    any of them
}