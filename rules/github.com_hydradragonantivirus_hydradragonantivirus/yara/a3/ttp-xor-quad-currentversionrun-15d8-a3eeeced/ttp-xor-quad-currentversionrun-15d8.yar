rule TTP_XOR_QUAD_CurrentVersionRun_15d8 {
  strings:
    $key_15d8 = { 46 b7 [2] 62 b9 [2] 49 95 [2] 67 b7 [2] 73 ac [2] 7c b6 [2] 62 ab [2] 60 aa [2] 7b ac [2] 67 ab [2] 7b 84 }

  condition:
    any of them
}