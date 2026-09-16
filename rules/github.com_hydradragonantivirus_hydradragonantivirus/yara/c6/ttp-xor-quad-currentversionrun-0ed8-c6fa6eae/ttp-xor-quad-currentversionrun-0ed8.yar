rule TTP_XOR_QUAD_CurrentVersionRun_0ed8 {
  strings:
    $key_0ed8 = { 5d b7 [2] 79 b9 [2] 52 95 [2] 7c b7 [2] 68 ac [2] 67 b6 [2] 79 ab [2] 7b aa [2] 60 ac [2] 7c ab [2] 60 84 }

  condition:
    any of them
}