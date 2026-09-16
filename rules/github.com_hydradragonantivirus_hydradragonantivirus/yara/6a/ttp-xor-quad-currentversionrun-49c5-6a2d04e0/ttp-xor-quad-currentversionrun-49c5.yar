rule TTP_XOR_QUAD_CurrentVersionRun_49c5 {
  strings:
    $key_49c5 = { 1a aa [2] 3e a4 [2] 15 88 [2] 3b aa [2] 2f b1 [2] 20 ab [2] 3e b6 [2] 3c b7 [2] 27 b1 [2] 3b b6 [2] 27 99 }

  condition:
    any of them
}