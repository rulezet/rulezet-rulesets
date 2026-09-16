rule TTP_XOR_QUAD_CurrentVersionRun_63d8 {
  strings:
    $key_63d8 = { 30 b7 [2] 14 b9 [2] 3f 95 [2] 11 b7 [2] 05 ac [2] 0a b6 [2] 14 ab [2] 16 aa [2] 0d ac [2] 11 ab [2] 0d 84 }

  condition:
    any of them
}