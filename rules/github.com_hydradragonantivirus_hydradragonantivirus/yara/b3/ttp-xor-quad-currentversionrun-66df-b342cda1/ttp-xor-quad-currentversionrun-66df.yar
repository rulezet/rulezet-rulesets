rule TTP_XOR_QUAD_CurrentVersionRun_66df {
  strings:
    $key_66df = { 35 b0 [2] 11 be [2] 3a 92 [2] 14 b0 [2] 00 ab [2] 0f b1 [2] 11 ac [2] 13 ad [2] 08 ab [2] 14 ac [2] 08 83 }

  condition:
    any of them
}