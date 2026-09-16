rule TTP_XOR_QUAD_CurrentVersionRun_d7df {
  strings:
    $key_d7df = { 84 b0 [2] a0 be [2] 8b 92 [2] a5 b0 [2] b1 ab [2] be b1 [2] a0 ac [2] a2 ad [2] b9 ab [2] a5 ac [2] b9 83 }

  condition:
    any of them
}