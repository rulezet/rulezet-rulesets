rule TTP_XOR_QUAD_CurrentVersionRun_1886 {
  strings:
    $key_1886 = { 4b e9 [2] 6f e7 [2] 44 cb [2] 6a e9 [2] 7e f2 [2] 71 e8 [2] 6f f5 [2] 6d f4 [2] 76 f2 [2] 6a f5 [2] 76 da }

  condition:
    any of them
}