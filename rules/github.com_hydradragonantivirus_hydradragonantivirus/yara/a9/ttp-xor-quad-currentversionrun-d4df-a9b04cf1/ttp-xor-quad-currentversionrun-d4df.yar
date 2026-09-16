rule TTP_XOR_QUAD_CurrentVersionRun_d4df {
  strings:
    $key_d4df = { 87 b0 [2] a3 be [2] 88 92 [2] a6 b0 [2] b2 ab [2] bd b1 [2] a3 ac [2] a1 ad [2] ba ab [2] a6 ac [2] ba 83 }

  condition:
    any of them
}