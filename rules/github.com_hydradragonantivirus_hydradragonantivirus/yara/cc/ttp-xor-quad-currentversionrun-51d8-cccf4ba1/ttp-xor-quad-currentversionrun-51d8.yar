rule TTP_XOR_QUAD_CurrentVersionRun_51d8 {
  strings:
    $key_51d8 = { 02 b7 [2] 26 b9 [2] 0d 95 [2] 23 b7 [2] 37 ac [2] 38 b6 [2] 26 ab [2] 24 aa [2] 3f ac [2] 23 ab [2] 3f 84 }

  condition:
    any of them
}