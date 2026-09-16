rule TTP_XOR_QUAD_CurrentVersionRun_22c4 {
  strings:
    $key_22c4 = { 71 ab [2] 55 a5 [2] 7e 89 [2] 50 ab [2] 44 b0 [2] 4b aa [2] 55 b7 [2] 57 b6 [2] 4c b0 [2] 50 b7 [2] 4c 98 }

  condition:
    any of them
}