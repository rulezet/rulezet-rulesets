rule TTP_XOR_QUAD_CurrentVersionRun_43d8 {
  strings:
    $key_43d8 = { 10 b7 [2] 34 b9 [2] 1f 95 [2] 31 b7 [2] 25 ac [2] 2a b6 [2] 34 ab [2] 36 aa [2] 2d ac [2] 31 ab [2] 2d 84 }

  condition:
    any of them
}