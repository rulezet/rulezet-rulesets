rule TTP_XOR_QUAD_CurrentVersionRun_71d8 {
  strings:
    $key_71d8 = { 22 b7 [2] 06 b9 [2] 2d 95 [2] 03 b7 [2] 17 ac [2] 18 b6 [2] 06 ab [2] 04 aa [2] 1f ac [2] 03 ab [2] 1f 84 }

  condition:
    any of them
}