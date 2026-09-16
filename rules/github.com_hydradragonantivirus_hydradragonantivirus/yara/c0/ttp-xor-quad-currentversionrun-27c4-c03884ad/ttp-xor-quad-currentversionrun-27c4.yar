rule TTP_XOR_QUAD_CurrentVersionRun_27c4 {
  strings:
    $key_27c4 = { 74 ab [2] 50 a5 [2] 7b 89 [2] 55 ab [2] 41 b0 [2] 4e aa [2] 50 b7 [2] 52 b6 [2] 49 b0 [2] 55 b7 [2] 49 98 }

  condition:
    any of them
}