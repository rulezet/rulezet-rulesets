rule TTP_XOR_QUAD_CurrentVersionRun_fbd8 {
  strings:
    $key_fbd8 = { a8 b7 [2] 8c b9 [2] a7 95 [2] 89 b7 [2] 9d ac [2] 92 b6 [2] 8c ab [2] 8e aa [2] 95 ac [2] 89 ab [2] 95 84 }

  condition:
    any of them
}