rule TTP_XOR_QUAD_CurrentVersionRun_0886 {
  strings:
    $key_0886 = { 5b e9 [2] 7f e7 [2] 54 cb [2] 7a e9 [2] 6e f2 [2] 61 e8 [2] 7f f5 [2] 7d f4 [2] 66 f2 [2] 7a f5 [2] 66 da }

  condition:
    any of them
}