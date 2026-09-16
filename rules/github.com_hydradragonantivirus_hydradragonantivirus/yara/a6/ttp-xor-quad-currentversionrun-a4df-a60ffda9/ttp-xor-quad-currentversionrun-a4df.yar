rule TTP_XOR_QUAD_CurrentVersionRun_a4df {
  strings:
    $key_a4df = { f7 b0 [2] d3 be [2] f8 92 [2] d6 b0 [2] c2 ab [2] cd b1 [2] d3 ac [2] d1 ad [2] ca ab [2] d6 ac [2] ca 83 }

  condition:
    any of them
}