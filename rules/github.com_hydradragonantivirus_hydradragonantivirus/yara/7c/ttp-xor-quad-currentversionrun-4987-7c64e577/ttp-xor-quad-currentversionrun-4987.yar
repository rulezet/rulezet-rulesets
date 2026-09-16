rule TTP_XOR_QUAD_CurrentVersionRun_4987 {
  strings:
    $key_4987 = { 1a e8 [2] 3e e6 [2] 15 ca [2] 3b e8 [2] 2f f3 [2] 20 e9 [2] 3e f4 [2] 3c f5 [2] 27 f3 [2] 3b f4 [2] 27 db }

  condition:
    any of them
}