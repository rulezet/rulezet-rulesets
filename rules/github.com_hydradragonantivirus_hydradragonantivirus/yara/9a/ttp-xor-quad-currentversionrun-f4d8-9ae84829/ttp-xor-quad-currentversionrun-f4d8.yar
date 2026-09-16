rule TTP_XOR_QUAD_CurrentVersionRun_f4d8 {
  strings:
    $key_f4d8 = { a7 b7 [2] 83 b9 [2] a8 95 [2] 86 b7 [2] 92 ac [2] 9d b6 [2] 83 ab [2] 81 aa [2] 9a ac [2] 86 ab [2] 9a 84 }

  condition:
    any of them
}