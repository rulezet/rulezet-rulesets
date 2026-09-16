rule TTP_XOR_QUAD_CurrentVersionRun_5287 {
  strings:
    $key_5287 = { 01 e8 [2] 25 e6 [2] 0e ca [2] 20 e8 [2] 34 f3 [2] 3b e9 [2] 25 f4 [2] 27 f5 [2] 3c f3 [2] 20 f4 [2] 3c db }

  condition:
    any of them
}