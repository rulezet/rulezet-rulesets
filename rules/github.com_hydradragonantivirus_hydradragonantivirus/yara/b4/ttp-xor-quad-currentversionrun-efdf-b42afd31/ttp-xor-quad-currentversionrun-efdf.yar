rule TTP_XOR_QUAD_CurrentVersionRun_efdf {
  strings:
    $key_efdf = { bc b0 [2] 98 be [2] b3 92 [2] 9d b0 [2] 89 ab [2] 86 b1 [2] 98 ac [2] 9a ad [2] 81 ab [2] 9d ac [2] 81 83 }

  condition:
    any of them
}