rule TTP_XOR_QUAD_CurrentVersionRun_30d8 {
  strings:
    $key_30d8 = { 63 b7 [2] 47 b9 [2] 6c 95 [2] 42 b7 [2] 56 ac [2] 59 b6 [2] 47 ab [2] 45 aa [2] 5e ac [2] 42 ab [2] 5e 84 }

  condition:
    any of them
}