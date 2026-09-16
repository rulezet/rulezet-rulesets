rule TTP_XOR_QUAD_CurrentVersionRun_c2df {
  strings:
    $key_c2df = { 91 b0 [2] b5 be [2] 9e 92 [2] b0 b0 [2] a4 ab [2] ab b1 [2] b5 ac [2] b7 ad [2] ac ab [2] b0 ac [2] ac 83 }

  condition:
    any of them
}