rule TTP_XOR_QUAD_CurrentVersionRun_5286 {
  strings:
    $key_5286 = { 01 e9 [2] 25 e7 [2] 0e cb [2] 20 e9 [2] 34 f2 [2] 3b e8 [2] 25 f5 [2] 27 f4 [2] 3c f2 [2] 20 f5 [2] 3c da }

  condition:
    any of them
}