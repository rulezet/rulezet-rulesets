rule TTP_XOR_QUAD_CurrentVersionRun_20d8 {
  strings:
    $key_20d8 = { 73 b7 [2] 57 b9 [2] 7c 95 [2] 52 b7 [2] 46 ac [2] 49 b6 [2] 57 ab [2] 55 aa [2] 4e ac [2] 52 ab [2] 4e 84 }

  condition:
    any of them
}