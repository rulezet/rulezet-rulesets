rule TTP_XOR_QUAD_CurrentVersionRun_0887 {
  strings:
    $key_0887 = { 5b e8 [2] 7f e6 [2] 54 ca [2] 7a e8 [2] 6e f3 [2] 61 e9 [2] 7f f4 [2] 7d f5 [2] 66 f3 [2] 7a f4 [2] 66 db }

  condition:
    any of them
}