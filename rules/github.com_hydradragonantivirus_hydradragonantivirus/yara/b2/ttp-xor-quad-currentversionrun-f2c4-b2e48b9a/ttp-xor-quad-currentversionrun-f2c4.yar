rule TTP_XOR_QUAD_CurrentVersionRun_f2c4 {
  strings:
    $key_f2c4 = { a1 ab [2] 85 a5 [2] ae 89 [2] 80 ab [2] 94 b0 [2] 9b aa [2] 85 b7 [2] 87 b6 [2] 9c b0 [2] 80 b7 [2] 9c 98 }

  condition:
    any of them
}