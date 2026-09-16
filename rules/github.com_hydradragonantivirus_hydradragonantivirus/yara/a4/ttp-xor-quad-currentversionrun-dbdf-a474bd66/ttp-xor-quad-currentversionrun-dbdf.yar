rule TTP_XOR_QUAD_CurrentVersionRun_dbdf {
  strings:
    $key_dbdf = { 88 b0 [2] ac be [2] 87 92 [2] a9 b0 [2] bd ab [2] b2 b1 [2] ac ac [2] ae ad [2] b5 ab [2] a9 ac [2] b5 83 }

  condition:
    any of them
}