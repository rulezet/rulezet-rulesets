rule TTP_XOR_QUAD_CurrentVersionRun_f7df {
  strings:
    $key_f7df = { a4 b0 [2] 80 be [2] ab 92 [2] 85 b0 [2] 91 ab [2] 9e b1 [2] 80 ac [2] 82 ad [2] 99 ab [2] 85 ac [2] 99 83 }

  condition:
    any of them
}