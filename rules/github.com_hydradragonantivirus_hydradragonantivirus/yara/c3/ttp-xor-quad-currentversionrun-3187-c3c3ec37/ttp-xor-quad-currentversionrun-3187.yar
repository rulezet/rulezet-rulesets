rule TTP_XOR_QUAD_CurrentVersionRun_3187 {
  strings:
    $key_3187 = { 62 e8 [2] 46 e6 [2] 6d ca [2] 43 e8 [2] 57 f3 [2] 58 e9 [2] 46 f4 [2] 44 f5 [2] 5f f3 [2] 43 f4 [2] 5f db }

  condition:
    any of them
}