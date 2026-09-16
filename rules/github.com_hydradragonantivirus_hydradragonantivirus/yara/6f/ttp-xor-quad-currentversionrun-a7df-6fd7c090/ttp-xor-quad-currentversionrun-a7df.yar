rule TTP_XOR_QUAD_CurrentVersionRun_a7df {
  strings:
    $key_a7df = { f4 b0 [2] d0 be [2] fb 92 [2] d5 b0 [2] c1 ab [2] ce b1 [2] d0 ac [2] d2 ad [2] c9 ab [2] d5 ac [2] c9 83 }

  condition:
    any of them
}