rule TTP_XOR_QUAD_CurrentVersionRun_d5df {
  strings:
    $key_d5df = { 86 b0 [2] a2 be [2] 89 92 [2] a7 b0 [2] b3 ab [2] bc b1 [2] a2 ac [2] a0 ad [2] bb ab [2] a7 ac [2] bb 83 }

  condition:
    any of them
}