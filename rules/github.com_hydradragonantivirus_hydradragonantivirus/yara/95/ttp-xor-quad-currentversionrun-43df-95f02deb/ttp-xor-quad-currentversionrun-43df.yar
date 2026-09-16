rule TTP_XOR_QUAD_CurrentVersionRun_43df {
  strings:
    $key_43df = { 10 b0 [2] 34 be [2] 1f 92 [2] 31 b0 [2] 25 ab [2] 2a b1 [2] 34 ac [2] 36 ad [2] 2d ab [2] 31 ac [2] 2d 83 }

  condition:
    any of them
}