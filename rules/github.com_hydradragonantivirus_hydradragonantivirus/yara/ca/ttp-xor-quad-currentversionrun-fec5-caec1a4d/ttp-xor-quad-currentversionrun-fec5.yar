rule TTP_XOR_QUAD_CurrentVersionRun_fec5 {
  strings:
    $key_fec5 = { ad aa [2] 89 a4 [2] a2 88 [2] 8c aa [2] 98 b1 [2] 97 ab [2] 89 b6 [2] 8b b7 [2] 90 b1 [2] 8c b6 [2] 90 99 }

  condition:
    any of them
}