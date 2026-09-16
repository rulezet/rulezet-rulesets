rule TTP_XOR_QUAD_CurrentVersionRun_b5df {
  strings:
    $key_b5df = { e6 b0 [2] c2 be [2] e9 92 [2] c7 b0 [2] d3 ab [2] dc b1 [2] c2 ac [2] c0 ad [2] db ab [2] c7 ac [2] db 83 }

  condition:
    any of them
}