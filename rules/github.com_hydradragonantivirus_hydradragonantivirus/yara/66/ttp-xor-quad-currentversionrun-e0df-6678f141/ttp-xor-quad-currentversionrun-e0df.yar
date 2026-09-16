rule TTP_XOR_QUAD_CurrentVersionRun_e0df {
  strings:
    $key_e0df = { b3 b0 [2] 97 be [2] bc 92 [2] 92 b0 [2] 86 ab [2] 89 b1 [2] 97 ac [2] 95 ad [2] 8e ab [2] 92 ac [2] 8e 83 }

  condition:
    any of them
}