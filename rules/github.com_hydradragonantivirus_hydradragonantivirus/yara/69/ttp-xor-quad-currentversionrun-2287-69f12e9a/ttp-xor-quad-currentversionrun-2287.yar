rule TTP_XOR_QUAD_CurrentVersionRun_2287 {
  strings:
    $key_2287 = { 71 e8 [2] 55 e6 [2] 7e ca [2] 50 e8 [2] 44 f3 [2] 4b e9 [2] 55 f4 [2] 57 f5 [2] 4c f3 [2] 50 f4 [2] 4c db }

  condition:
    any of them
}