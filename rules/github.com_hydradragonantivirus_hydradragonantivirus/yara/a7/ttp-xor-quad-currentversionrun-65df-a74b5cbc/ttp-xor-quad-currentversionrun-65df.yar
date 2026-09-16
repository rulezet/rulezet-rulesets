rule TTP_XOR_QUAD_CurrentVersionRun_65df {
  strings:
    $key_65df = { 36 b0 [2] 12 be [2] 39 92 [2] 17 b0 [2] 03 ab [2] 0c b1 [2] 12 ac [2] 10 ad [2] 0b ab [2] 17 ac [2] 0b 83 }

  condition:
    any of them
}