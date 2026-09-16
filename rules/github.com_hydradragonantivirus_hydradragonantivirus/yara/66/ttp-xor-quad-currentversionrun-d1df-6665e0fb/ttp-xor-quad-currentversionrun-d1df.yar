rule TTP_XOR_QUAD_CurrentVersionRun_d1df {
  strings:
    $key_d1df = { 82 b0 [2] a6 be [2] 8d 92 [2] a3 b0 [2] b7 ab [2] b8 b1 [2] a6 ac [2] a4 ad [2] bf ab [2] a3 ac [2] bf 83 }

  condition:
    any of them
}