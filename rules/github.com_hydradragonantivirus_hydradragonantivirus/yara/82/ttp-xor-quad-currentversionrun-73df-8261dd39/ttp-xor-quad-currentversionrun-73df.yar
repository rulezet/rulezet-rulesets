rule TTP_XOR_QUAD_CurrentVersionRun_73df {
  strings:
    $key_73df = { 20 b0 [2] 04 be [2] 2f 92 [2] 01 b0 [2] 15 ab [2] 1a b1 [2] 04 ac [2] 06 ad [2] 1d ab [2] 01 ac [2] 1d 83 }

  condition:
    any of them
}