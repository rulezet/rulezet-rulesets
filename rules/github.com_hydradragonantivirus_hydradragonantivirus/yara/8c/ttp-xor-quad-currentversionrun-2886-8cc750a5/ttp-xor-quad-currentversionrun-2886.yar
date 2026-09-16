rule TTP_XOR_QUAD_CurrentVersionRun_2886 {
  strings:
    $key_2886 = { 7b e9 [2] 5f e7 [2] 74 cb [2] 5a e9 [2] 4e f2 [2] 41 e8 [2] 5f f5 [2] 5d f4 [2] 46 f2 [2] 5a f5 [2] 46 da }

  condition:
    any of them
}