rule TTP_XOR_QUAD_CurrentVersionRun_16df {
  strings:
    $key_16df = { 45 b0 [2] 61 be [2] 4a 92 [2] 64 b0 [2] 70 ab [2] 7f b1 [2] 61 ac [2] 63 ad [2] 78 ab [2] 64 ac [2] 78 83 }

  condition:
    any of them
}