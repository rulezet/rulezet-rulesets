rule TTP_XOR_QUAD_CurrentVersionRun_4ec4 {
  strings:
    $key_4ec4 = { 1d ab [2] 39 a5 [2] 12 89 [2] 3c ab [2] 28 b0 [2] 27 aa [2] 39 b7 [2] 3b b6 [2] 20 b0 [2] 3c b7 [2] 20 98 }

  condition:
    any of them
}