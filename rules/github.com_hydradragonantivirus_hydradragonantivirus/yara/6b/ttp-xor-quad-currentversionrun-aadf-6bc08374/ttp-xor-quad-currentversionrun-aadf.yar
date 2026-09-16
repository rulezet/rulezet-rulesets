rule TTP_XOR_QUAD_CurrentVersionRun_aadf {
  strings:
    $key_aadf = { f9 b0 [2] dd be [2] f6 92 [2] d8 b0 [2] cc ab [2] c3 b1 [2] dd ac [2] df ad [2] c4 ab [2] d8 ac [2] c4 83 }

  condition:
    any of them
}