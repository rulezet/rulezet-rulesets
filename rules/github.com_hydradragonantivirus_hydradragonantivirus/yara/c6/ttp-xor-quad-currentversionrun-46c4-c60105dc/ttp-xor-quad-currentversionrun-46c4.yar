rule TTP_XOR_QUAD_CurrentVersionRun_46c4 {
  strings:
    $key_46c4 = { 15 ab [2] 31 a5 [2] 1a 89 [2] 34 ab [2] 20 b0 [2] 2f aa [2] 31 b7 [2] 33 b6 [2] 28 b0 [2] 34 b7 [2] 28 98 }

  condition:
    any of them
}