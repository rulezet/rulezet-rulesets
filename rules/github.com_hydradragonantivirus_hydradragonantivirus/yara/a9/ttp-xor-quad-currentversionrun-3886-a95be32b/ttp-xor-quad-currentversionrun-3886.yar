rule TTP_XOR_QUAD_CurrentVersionRun_3886 {
  strings:
    $key_3886 = { 6b e9 [2] 4f e7 [2] 64 cb [2] 4a e9 [2] 5e f2 [2] 51 e8 [2] 4f f5 [2] 4d f4 [2] 56 f2 [2] 4a f5 [2] 56 da }

  condition:
    any of them
}