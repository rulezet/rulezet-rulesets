rule TTP_XOR_QUAD_CurrentVersionRun_35df {
  strings:
    $key_35df = { 66 b0 [2] 42 be [2] 69 92 [2] 47 b0 [2] 53 ab [2] 5c b1 [2] 42 ac [2] 40 ad [2] 5b ab [2] 47 ac [2] 5b 83 }

  condition:
    any of them
}