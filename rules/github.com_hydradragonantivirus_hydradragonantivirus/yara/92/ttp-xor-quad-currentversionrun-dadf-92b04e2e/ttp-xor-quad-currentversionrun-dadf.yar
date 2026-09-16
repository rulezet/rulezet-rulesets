rule TTP_XOR_QUAD_CurrentVersionRun_dadf {
  strings:
    $key_dadf = { 89 b0 [2] ad be [2] 86 92 [2] a8 b0 [2] bc ab [2] b3 b1 [2] ad ac [2] af ad [2] b4 ab [2] a8 ac [2] b4 83 }

  condition:
    any of them
}