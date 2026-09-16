rule TTP_XOR_QUAD_CurrentVersionRun_75df {
  strings:
    $key_75df = { 26 b0 [2] 02 be [2] 29 92 [2] 07 b0 [2] 13 ab [2] 1c b1 [2] 02 ac [2] 00 ad [2] 1b ab [2] 07 ac [2] 1b 83 }

  condition:
    any of them
}