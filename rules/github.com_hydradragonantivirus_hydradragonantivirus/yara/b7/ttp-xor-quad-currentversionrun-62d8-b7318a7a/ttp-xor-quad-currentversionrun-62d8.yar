rule TTP_XOR_QUAD_CurrentVersionRun_62d8 {
  strings:
    $key_62d8 = { 31 b7 [2] 15 b9 [2] 3e 95 [2] 10 b7 [2] 04 ac [2] 0b b6 [2] 15 ab [2] 17 aa [2] 0c ac [2] 10 ab [2] 0c 84 }

  condition:
    any of them
}