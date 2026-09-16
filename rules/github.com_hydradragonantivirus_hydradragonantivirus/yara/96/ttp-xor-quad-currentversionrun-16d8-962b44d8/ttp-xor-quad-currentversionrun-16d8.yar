rule TTP_XOR_QUAD_CurrentVersionRun_16d8 {
  strings:
    $key_16d8 = { 45 b7 [2] 61 b9 [2] 4a 95 [2] 64 b7 [2] 70 ac [2] 7f b6 [2] 61 ab [2] 63 aa [2] 78 ac [2] 64 ab [2] 78 84 }

  condition:
    any of them
}