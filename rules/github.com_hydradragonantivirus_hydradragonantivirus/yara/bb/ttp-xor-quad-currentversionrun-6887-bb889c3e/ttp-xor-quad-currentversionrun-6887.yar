rule TTP_XOR_QUAD_CurrentVersionRun_6887 {
  strings:
    $key_6887 = { 3b e8 [2] 1f e6 [2] 34 ca [2] 1a e8 [2] 0e f3 [2] 01 e9 [2] 1f f4 [2] 1d f5 [2] 06 f3 [2] 1a f4 [2] 06 db }

  condition:
    any of them
}