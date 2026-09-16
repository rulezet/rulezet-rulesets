rule TTP_XOR_QUAD_CurrentVersionRun_41df {
  strings:
    $key_41df = { 12 b0 [2] 36 be [2] 1d 92 [2] 33 b0 [2] 27 ab [2] 28 b1 [2] 36 ac [2] 34 ad [2] 2f ab [2] 33 ac [2] 2f 83 }

  condition:
    any of them
}