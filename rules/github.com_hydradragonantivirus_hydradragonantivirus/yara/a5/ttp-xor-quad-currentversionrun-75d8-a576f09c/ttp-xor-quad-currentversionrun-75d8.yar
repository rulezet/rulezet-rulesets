rule TTP_XOR_QUAD_CurrentVersionRun_75d8 {
  strings:
    $key_75d8 = { 26 b7 [2] 02 b9 [2] 29 95 [2] 07 b7 [2] 13 ac [2] 1c b6 [2] 02 ab [2] 00 aa [2] 1b ac [2] 07 ab [2] 1b 84 }

  condition:
    any of them
}