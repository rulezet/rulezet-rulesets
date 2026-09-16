rule TTP_XOR_QUAD_CurrentVersionRun_c4df {
  strings:
    $key_c4df = { 97 b0 [2] b3 be [2] 98 92 [2] b6 b0 [2] a2 ab [2] ad b1 [2] b3 ac [2] b1 ad [2] aa ab [2] b6 ac [2] aa 83 }

  condition:
    any of them
}