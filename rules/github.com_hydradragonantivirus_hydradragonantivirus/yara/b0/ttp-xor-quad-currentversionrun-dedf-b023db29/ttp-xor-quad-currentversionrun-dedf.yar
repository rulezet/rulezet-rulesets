rule TTP_XOR_QUAD_CurrentVersionRun_dedf {
  strings:
    $key_dedf = { 8d b0 [2] a9 be [2] 82 92 [2] ac b0 [2] b8 ab [2] b7 b1 [2] a9 ac [2] ab ad [2] b0 ab [2] ac ac [2] b0 83 }

  condition:
    any of them
}