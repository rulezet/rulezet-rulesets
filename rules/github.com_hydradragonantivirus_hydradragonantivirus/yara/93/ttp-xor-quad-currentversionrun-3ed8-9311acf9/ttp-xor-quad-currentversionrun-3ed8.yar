rule TTP_XOR_QUAD_CurrentVersionRun_3ed8 {
  strings:
    $key_3ed8 = { 6d b7 [2] 49 b9 [2] 62 95 [2] 4c b7 [2] 58 ac [2] 57 b6 [2] 49 ab [2] 4b aa [2] 50 ac [2] 4c ab [2] 50 84 }

  condition:
    any of them
}