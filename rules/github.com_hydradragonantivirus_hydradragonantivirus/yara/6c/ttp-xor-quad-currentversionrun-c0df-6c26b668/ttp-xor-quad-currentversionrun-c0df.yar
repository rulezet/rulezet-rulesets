rule TTP_XOR_QUAD_CurrentVersionRun_c0df {
  strings:
    $key_c0df = { 93 b0 [2] b7 be [2] 9c 92 [2] b2 b0 [2] a6 ab [2] a9 b1 [2] b7 ac [2] b5 ad [2] ae ab [2] b2 ac [2] ae 83 }

  condition:
    any of them
}