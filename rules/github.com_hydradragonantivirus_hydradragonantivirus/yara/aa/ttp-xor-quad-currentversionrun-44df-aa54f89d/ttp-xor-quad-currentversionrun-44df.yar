rule TTP_XOR_QUAD_CurrentVersionRun_44df {
  strings:
    $key_44df = { 17 b0 [2] 33 be [2] 18 92 [2] 36 b0 [2] 22 ab [2] 2d b1 [2] 33 ac [2] 31 ad [2] 2a ab [2] 36 ac [2] 2a 83 }

  condition:
    any of them
}