rule TTP_XOR_QUAD_CurrentVersionRun_47d8 {
  strings:
    $key_47d8 = { 14 b7 [2] 30 b9 [2] 1b 95 [2] 35 b7 [2] 21 ac [2] 2e b6 [2] 30 ab [2] 32 aa [2] 29 ac [2] 35 ab [2] 29 84 }

  condition:
    any of them
}