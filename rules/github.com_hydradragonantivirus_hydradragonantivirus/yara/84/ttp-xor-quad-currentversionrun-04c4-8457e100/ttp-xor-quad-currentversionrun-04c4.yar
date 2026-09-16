rule TTP_XOR_QUAD_CurrentVersionRun_04c4 {
  strings:
    $key_04c4 = { 57 ab [2] 73 a5 [2] 58 89 [2] 76 ab [2] 62 b0 [2] 6d aa [2] 73 b7 [2] 71 b6 [2] 6a b0 [2] 76 b7 [2] 6a 98 }

  condition:
    any of them
}