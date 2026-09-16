rule TTP_XOR_QUAD_CurrentVersionRun_c7df {
  strings:
    $key_c7df = { 94 b0 [2] b0 be [2] 9b 92 [2] b5 b0 [2] a1 ab [2] ae b1 [2] b0 ac [2] b2 ad [2] a9 ab [2] b5 ac [2] a9 83 }

  condition:
    any of them
}