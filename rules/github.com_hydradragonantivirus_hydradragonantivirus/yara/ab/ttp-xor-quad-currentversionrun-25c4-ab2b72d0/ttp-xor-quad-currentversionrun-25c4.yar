rule TTP_XOR_QUAD_CurrentVersionRun_25c4 {
  strings:
    $key_25c4 = { 76 ab [2] 52 a5 [2] 79 89 [2] 57 ab [2] 43 b0 [2] 4c aa [2] 52 b7 [2] 50 b6 [2] 4b b0 [2] 57 b7 [2] 4b 98 }

  condition:
    any of them
}