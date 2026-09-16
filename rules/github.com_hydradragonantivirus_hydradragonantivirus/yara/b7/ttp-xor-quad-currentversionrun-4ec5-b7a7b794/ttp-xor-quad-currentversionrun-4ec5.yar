rule TTP_XOR_QUAD_CurrentVersionRun_4ec5 {
  strings:
    $key_4ec5 = { 1d aa [2] 39 a4 [2] 12 88 [2] 3c aa [2] 28 b1 [2] 27 ab [2] 39 b6 [2] 3b b7 [2] 20 b1 [2] 3c b6 [2] 20 99 }

  condition:
    any of them
}