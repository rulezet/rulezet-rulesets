rule TTP_XOR_QUAD_CurrentVersionRun_e6df {
  strings:
    $key_e6df = { b5 b0 [2] 91 be [2] ba 92 [2] 94 b0 [2] 80 ab [2] 8f b1 [2] 91 ac [2] 93 ad [2] 88 ab [2] 94 ac [2] 88 83 }

  condition:
    any of them
}