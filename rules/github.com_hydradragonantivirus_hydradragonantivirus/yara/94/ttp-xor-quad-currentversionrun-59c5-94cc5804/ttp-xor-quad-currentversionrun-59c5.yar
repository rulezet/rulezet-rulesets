rule TTP_XOR_QUAD_CurrentVersionRun_59c5 {
  strings:
    $key_59c5 = { 0a aa [2] 2e a4 [2] 05 88 [2] 2b aa [2] 3f b1 [2] 30 ab [2] 2e b6 [2] 2c b7 [2] 37 b1 [2] 2b b6 [2] 37 99 }

  condition:
    any of them
}