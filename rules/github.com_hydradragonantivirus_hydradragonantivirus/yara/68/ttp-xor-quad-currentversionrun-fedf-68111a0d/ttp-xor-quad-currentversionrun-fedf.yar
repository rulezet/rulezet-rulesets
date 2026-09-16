rule TTP_XOR_QUAD_CurrentVersionRun_fedf {
  strings:
    $key_fedf = { ad b0 [2] 89 be [2] a2 92 [2] 8c b0 [2] 98 ab [2] 97 b1 [2] 89 ac [2] 8b ad [2] 90 ab [2] 8c ac [2] 90 83 }

  condition:
    any of them
}