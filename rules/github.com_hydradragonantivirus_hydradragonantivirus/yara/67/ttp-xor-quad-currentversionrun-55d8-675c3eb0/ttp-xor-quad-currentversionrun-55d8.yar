rule TTP_XOR_QUAD_CurrentVersionRun_55d8 {
  strings:
    $key_55d8 = { 06 b7 [2] 22 b9 [2] 09 95 [2] 27 b7 [2] 33 ac [2] 3c b6 [2] 22 ab [2] 20 aa [2] 3b ac [2] 27 ab [2] 3b 84 }

  condition:
    any of them
}