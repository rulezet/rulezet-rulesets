rule TTP_XOR_QUAD_CurrentVersionRun_3887 {
  strings:
    $key_3887 = { 6b e8 [2] 4f e6 [2] 64 ca [2] 4a e8 [2] 5e f3 [2] 51 e9 [2] 4f f4 [2] 4d f5 [2] 56 f3 [2] 4a f4 [2] 56 db }

  condition:
    any of them
}