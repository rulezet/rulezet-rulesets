rule TTP_XOR_QUAD_CurrentVersionRun_47c4 {
  strings:
    $key_47c4 = { 14 ab [2] 30 a5 [2] 1b 89 [2] 35 ab [2] 21 b0 [2] 2e aa [2] 30 b7 [2] 32 b6 [2] 29 b0 [2] 35 b7 [2] 29 98 }

  condition:
    any of them
}