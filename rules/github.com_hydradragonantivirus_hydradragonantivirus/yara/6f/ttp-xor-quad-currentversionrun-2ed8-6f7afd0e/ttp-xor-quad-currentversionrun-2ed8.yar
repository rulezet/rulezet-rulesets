rule TTP_XOR_QUAD_CurrentVersionRun_2ed8 {
  strings:
    $key_2ed8 = { 7d b7 [2] 59 b9 [2] 72 95 [2] 5c b7 [2] 48 ac [2] 47 b6 [2] 59 ab [2] 5b aa [2] 40 ac [2] 5c ab [2] 40 84 }

  condition:
    any of them
}