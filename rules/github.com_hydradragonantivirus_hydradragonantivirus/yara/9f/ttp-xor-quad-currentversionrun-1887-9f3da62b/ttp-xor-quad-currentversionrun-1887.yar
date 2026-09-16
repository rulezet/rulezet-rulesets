rule TTP_XOR_QUAD_CurrentVersionRun_1887 {
  strings:
    $key_1887 = { 4b e8 [2] 6f e6 [2] 44 ca [2] 6a e8 [2] 7e f3 [2] 71 e9 [2] 6f f4 [2] 6d f5 [2] 76 f3 [2] 6a f4 [2] 76 db }

  condition:
    any of them
}