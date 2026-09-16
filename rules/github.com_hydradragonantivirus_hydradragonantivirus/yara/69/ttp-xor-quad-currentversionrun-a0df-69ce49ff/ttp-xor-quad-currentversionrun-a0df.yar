rule TTP_XOR_QUAD_CurrentVersionRun_a0df {
  strings:
    $key_a0df = { f3 b0 [2] d7 be [2] fc 92 [2] d2 b0 [2] c6 ab [2] c9 b1 [2] d7 ac [2] d5 ad [2] ce ab [2] d2 ac [2] ce 83 }

  condition:
    any of them
}