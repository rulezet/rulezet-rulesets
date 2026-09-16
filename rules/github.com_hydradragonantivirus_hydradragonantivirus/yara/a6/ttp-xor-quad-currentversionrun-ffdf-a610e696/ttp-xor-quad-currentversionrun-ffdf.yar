rule TTP_XOR_QUAD_CurrentVersionRun_ffdf {
  strings:
    $key_ffdf = { ac b0 [2] 88 be [2] a3 92 [2] 8d b0 [2] 99 ab [2] 96 b1 [2] 88 ac [2] 8a ad [2] 91 ab [2] 8d ac [2] 91 83 }

  condition:
    any of them
}