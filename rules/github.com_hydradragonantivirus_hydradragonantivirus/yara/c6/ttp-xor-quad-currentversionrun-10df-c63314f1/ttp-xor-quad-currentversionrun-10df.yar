rule TTP_XOR_QUAD_CurrentVersionRun_10df {
  strings:
    $key_10df = { 43 b0 [2] 67 be [2] 4c 92 [2] 62 b0 [2] 76 ab [2] 79 b1 [2] 67 ac [2] 65 ad [2] 7e ab [2] 62 ac [2] 7e 83 }

  condition:
    any of them
}