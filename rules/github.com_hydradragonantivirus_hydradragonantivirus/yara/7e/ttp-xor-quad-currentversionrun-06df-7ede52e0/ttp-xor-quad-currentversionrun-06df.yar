rule TTP_XOR_QUAD_CurrentVersionRun_06df {
  strings:
    $key_06df = { 55 b0 [2] 71 be [2] 5a 92 [2] 74 b0 [2] 60 ab [2] 6f b1 [2] 71 ac [2] 73 ad [2] 68 ab [2] 74 ac [2] 68 83 }

  condition:
    any of them
}