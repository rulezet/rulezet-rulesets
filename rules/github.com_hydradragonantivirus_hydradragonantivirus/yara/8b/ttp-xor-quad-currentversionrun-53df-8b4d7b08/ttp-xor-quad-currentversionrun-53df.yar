rule TTP_XOR_QUAD_CurrentVersionRun_53df {
  strings:
    $key_53df = { 00 b0 [2] 24 be [2] 0f 92 [2] 21 b0 [2] 35 ab [2] 3a b1 [2] 24 ac [2] 26 ad [2] 3d ab [2] 21 ac [2] 3d 83 }

  condition:
    any of them
}