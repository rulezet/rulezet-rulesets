rule TTP_XOR_QUAD_CurrentVersionRun_eedf {
  strings:
    $key_eedf = { bd b0 [2] 99 be [2] b2 92 [2] 9c b0 [2] 88 ab [2] 87 b1 [2] 99 ac [2] 9b ad [2] 80 ab [2] 9c ac [2] 80 83 }

  condition:
    any of them
}