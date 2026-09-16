rule TTP_XOR_QUAD_CurrentVersionRun_57df {
  strings:
    $key_57df = { 04 b0 [2] 20 be [2] 0b 92 [2] 25 b0 [2] 31 ab [2] 3e b1 [2] 20 ac [2] 22 ad [2] 39 ab [2] 25 ac [2] 39 83 }

  condition:
    any of them
}