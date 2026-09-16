rule TTP_XOR_QUAD_CurrentVersionRun_64c4 {
  strings:
    $key_64c4 = { 37 ab [2] 13 a5 [2] 38 89 [2] 16 ab [2] 02 b0 [2] 0d aa [2] 13 b7 [2] 11 b6 [2] 0a b0 [2] 16 b7 [2] 0a 98 }

  condition:
    any of them
}