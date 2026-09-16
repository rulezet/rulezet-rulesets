rule TTP_XOR_QUAD_CurrentVersionRun_e2df {
  strings:
    $key_e2df = { b1 b0 [2] 95 be [2] be 92 [2] 90 b0 [2] 84 ab [2] 8b b1 [2] 95 ac [2] 97 ad [2] 8c ab [2] 90 ac [2] 8c 83 }

  condition:
    any of them
}