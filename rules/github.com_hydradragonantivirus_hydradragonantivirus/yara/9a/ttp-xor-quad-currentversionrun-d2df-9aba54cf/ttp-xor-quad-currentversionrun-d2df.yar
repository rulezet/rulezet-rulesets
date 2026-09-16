rule TTP_XOR_QUAD_CurrentVersionRun_d2df {
  strings:
    $key_d2df = { 81 b0 [2] a5 be [2] 8e 92 [2] a0 b0 [2] b4 ab [2] bb b1 [2] a5 ac [2] a7 ad [2] bc ab [2] a0 ac [2] bc 83 }

  condition:
    any of them
}