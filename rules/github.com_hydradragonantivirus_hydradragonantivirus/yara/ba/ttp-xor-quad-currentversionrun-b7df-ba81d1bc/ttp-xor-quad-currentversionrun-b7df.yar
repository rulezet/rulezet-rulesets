rule TTP_XOR_QUAD_CurrentVersionRun_b7df {
  strings:
    $key_b7df = { e4 b0 [2] c0 be [2] eb 92 [2] c5 b0 [2] d1 ab [2] de b1 [2] c0 ac [2] c2 ad [2] d9 ab [2] c5 ac [2] d9 83 }

  condition:
    any of them
}