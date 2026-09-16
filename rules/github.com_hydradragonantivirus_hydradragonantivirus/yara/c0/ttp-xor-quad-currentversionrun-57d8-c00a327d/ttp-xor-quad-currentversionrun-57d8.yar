rule TTP_XOR_QUAD_CurrentVersionRun_57d8 {
  strings:
    $key_57d8 = { 04 b7 [2] 20 b9 [2] 0b 95 [2] 25 b7 [2] 31 ac [2] 3e b6 [2] 20 ab [2] 22 aa [2] 39 ac [2] 25 ab [2] 39 84 }

  condition:
    any of them
}