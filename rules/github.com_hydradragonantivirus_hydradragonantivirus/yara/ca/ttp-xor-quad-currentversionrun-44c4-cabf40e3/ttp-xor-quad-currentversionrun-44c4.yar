rule TTP_XOR_QUAD_CurrentVersionRun_44c4 {
  strings:
    $key_44c4 = { 17 ab [2] 33 a5 [2] 18 89 [2] 36 ab [2] 22 b0 [2] 2d aa [2] 33 b7 [2] 31 b6 [2] 2a b0 [2] 36 b7 [2] 2a 98 }

  condition:
    any of them
}