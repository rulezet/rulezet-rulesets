rule TTP_XOR_QUAD_CurrentVersionRun_ebd8 {
  strings:
    $key_ebd8 = { b8 b7 [2] 9c b9 [2] b7 95 [2] 99 b7 [2] 8d ac [2] 82 b6 [2] 9c ab [2] 9e aa [2] 85 ac [2] 99 ab [2] 85 84 }

  condition:
    any of them
}