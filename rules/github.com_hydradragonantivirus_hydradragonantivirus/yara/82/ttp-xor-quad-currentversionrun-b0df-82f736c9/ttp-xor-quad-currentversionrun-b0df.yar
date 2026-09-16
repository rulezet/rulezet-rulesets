rule TTP_XOR_QUAD_CurrentVersionRun_b0df {
  strings:
    $key_b0df = { e3 b0 [2] c7 be [2] ec 92 [2] c2 b0 [2] d6 ab [2] d9 b1 [2] c7 ac [2] c5 ad [2] de ab [2] c2 ac [2] de 83 }

  condition:
    any of them
}