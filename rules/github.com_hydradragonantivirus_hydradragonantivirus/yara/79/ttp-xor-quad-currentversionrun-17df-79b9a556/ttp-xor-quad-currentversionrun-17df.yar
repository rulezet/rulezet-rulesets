rule TTP_XOR_QUAD_CurrentVersionRun_17df {
  strings:
    $key_17df = { 44 b0 [2] 60 be [2] 4b 92 [2] 65 b0 [2] 71 ab [2] 7e b1 [2] 60 ac [2] 62 ad [2] 79 ab [2] 65 ac [2] 79 83 }

  condition:
    any of them
}