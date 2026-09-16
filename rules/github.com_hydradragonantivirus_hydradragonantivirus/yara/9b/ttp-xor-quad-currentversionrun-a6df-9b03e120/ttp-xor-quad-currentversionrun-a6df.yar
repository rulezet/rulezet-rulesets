rule TTP_XOR_QUAD_CurrentVersionRun_a6df {
  strings:
    $key_a6df = { f5 b0 [2] d1 be [2] fa 92 [2] d4 b0 [2] c0 ab [2] cf b1 [2] d1 ac [2] d3 ad [2] c8 ab [2] d4 ac [2] c8 83 }

  condition:
    any of them
}