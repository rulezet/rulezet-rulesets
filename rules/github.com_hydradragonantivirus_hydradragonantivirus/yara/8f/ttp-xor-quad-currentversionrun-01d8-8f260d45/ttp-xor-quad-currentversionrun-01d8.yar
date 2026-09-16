rule TTP_XOR_QUAD_CurrentVersionRun_01d8 {
  strings:
    $key_01d8 = { 52 b7 [2] 76 b9 [2] 5d 95 [2] 73 b7 [2] 67 ac [2] 68 b6 [2] 76 ab [2] 74 aa [2] 6f ac [2] 73 ab [2] 6f 84 }

  condition:
    any of them
}