rule TTP_XOR_QUAD_CurrentVersionRun_06d8 {
  strings:
    $key_06d8 = { 55 b7 [2] 71 b9 [2] 5a 95 [2] 74 b7 [2] 60 ac [2] 6f b6 [2] 71 ab [2] 73 aa [2] 68 ac [2] 74 ab [2] 68 84 }

  condition:
    any of them
}