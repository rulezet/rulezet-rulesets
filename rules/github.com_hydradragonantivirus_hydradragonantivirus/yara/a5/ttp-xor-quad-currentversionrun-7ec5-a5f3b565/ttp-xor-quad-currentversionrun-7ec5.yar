rule TTP_XOR_QUAD_CurrentVersionRun_7ec5 {
  strings:
    $key_7ec5 = { 2d aa [2] 09 a4 [2] 22 88 [2] 0c aa [2] 18 b1 [2] 17 ab [2] 09 b6 [2] 0b b7 [2] 10 b1 [2] 0c b6 [2] 10 99 }

  condition:
    any of them
}