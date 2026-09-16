rule TTP_XOR_QUAD_CurrentVersionRun_badf {
  strings:
    $key_badf = { e9 b0 [2] cd be [2] e6 92 [2] c8 b0 [2] dc ab [2] d3 b1 [2] cd ac [2] cf ad [2] d4 ab [2] c8 ac [2] d4 83 }

  condition:
    any of them
}