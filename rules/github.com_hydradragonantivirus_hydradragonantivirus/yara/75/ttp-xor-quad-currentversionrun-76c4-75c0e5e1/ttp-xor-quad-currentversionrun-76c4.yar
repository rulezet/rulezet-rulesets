rule TTP_XOR_QUAD_CurrentVersionRun_76c4 {
  strings:
    $key_76c4 = { 25 ab [2] 01 a5 [2] 2a 89 [2] 04 ab [2] 10 b0 [2] 1f aa [2] 01 b7 [2] 03 b6 [2] 18 b0 [2] 04 b7 [2] 18 98 }

  condition:
    any of them
}