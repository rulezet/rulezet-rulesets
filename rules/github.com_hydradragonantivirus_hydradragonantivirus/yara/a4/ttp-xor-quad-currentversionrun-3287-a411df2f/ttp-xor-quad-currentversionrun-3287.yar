rule TTP_XOR_QUAD_CurrentVersionRun_3287 {
  strings:
    $key_3287 = { 61 e8 [2] 45 e6 [2] 6e ca [2] 40 e8 [2] 54 f3 [2] 5b e9 [2] 45 f4 [2] 47 f5 [2] 5c f3 [2] 40 f4 [2] 5c db }

  condition:
    any of them
}