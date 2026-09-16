rule TTP_XOR_QUAD_CurrentVersionRun_eed8 {
  strings:
    $key_eed8 = { bd b7 [2] 99 b9 [2] b2 95 [2] 9c b7 [2] 88 ac [2] 87 b6 [2] 99 ab [2] 9b aa [2] 80 ac [2] 9c ab [2] 80 84 }

  condition:
    any of them
}