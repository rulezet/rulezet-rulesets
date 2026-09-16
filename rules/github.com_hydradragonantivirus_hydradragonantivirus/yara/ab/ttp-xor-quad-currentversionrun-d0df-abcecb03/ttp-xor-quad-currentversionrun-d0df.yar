rule TTP_XOR_QUAD_CurrentVersionRun_d0df {
  strings:
    $key_d0df = { 83 b0 [2] a7 be [2] 8c 92 [2] a2 b0 [2] b6 ab [2] b9 b1 [2] a7 ac [2] a5 ad [2] be ab [2] a2 ac [2] be 83 }

  condition:
    any of them
}