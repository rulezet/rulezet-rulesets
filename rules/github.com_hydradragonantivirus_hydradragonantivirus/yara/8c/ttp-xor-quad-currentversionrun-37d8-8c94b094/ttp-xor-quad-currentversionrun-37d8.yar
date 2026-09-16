rule TTP_XOR_QUAD_CurrentVersionRun_37d8 {
  strings:
    $key_37d8 = { 64 b7 [2] 40 b9 [2] 6b 95 [2] 45 b7 [2] 51 ac [2] 5e b6 [2] 40 ab [2] 42 aa [2] 59 ac [2] 45 ab [2] 59 84 }

  condition:
    any of them
}